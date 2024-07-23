package web

import (
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/proxati/mitmproxy/proxy"
)

type breakPointRule struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Action int    `json:"action"` // 1 - change request 2 - change response 3 - both
}

type concurrentConn struct {
	conn *websocket.Conn
	mu   sync.Mutex

	sendConnMessageMap map[string]bool

	waitChans   map[string]chan interface{}
	waitChansMu sync.Mutex

	breakPointRules []*breakPointRule
}

func newConn(c *websocket.Conn) *concurrentConn {
	return &concurrentConn{
		conn:               c,
		sendConnMessageMap: make(map[string]bool),
		waitChans:          make(map[string]chan interface{}),
	}
}

func (c *concurrentConn) trySendConnMessage(f *proxy.Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := f.ConnContext.ID().String()
	if send := c.sendConnMessageMap[key]; send {
		return
	}
	c.sendConnMessageMap[key] = true
	msg := newMessageFlow(messageTypeConn, f)
	err := c.conn.WriteMessage(websocket.BinaryMessage, msg.bytes())
	if err != nil {
		sLogger.Error("could not write to websocket", "error", err)
		return
	}
}

func (c *concurrentConn) whenConnClose(connCtx *proxy.ConnContext) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.sendConnMessageMap, connCtx.ID().String())

	msg := newMessageConnClose(connCtx)
	err := c.conn.WriteMessage(websocket.BinaryMessage, msg.bytes())
	if err != nil {
		sLogger.Error("could not write to websocket during close", "error", err)
		return
	}
}

func (c *concurrentConn) writeMessage(msg *messageFlow, f *proxy.Flow) {
	if c.isIntercpt(f, msg) {
		msg.waitIntercept = 1
	}

	c.mu.Lock()
	err := c.conn.WriteMessage(websocket.BinaryMessage, msg.bytes())
	c.mu.Unlock()
	if err != nil {
		sLogger.Error("could not WriteMessage", "error", err)
		return
	}

	if msg.waitIntercept == 1 {
		c.waitIntercept(f, msg)
	}
}

func (c *concurrentConn) readloop() {
	for {
		mt, data, err := c.conn.ReadMessage()
		if err != nil {
			sLogger.Error("could not ReadMessage", "error", err)
			break
		}

		if mt != websocket.BinaryMessage {
			sLogger.Warn("not BinaryMessage, skipping")
			continue
		}

		msg := parseMessage(data)
		if msg == nil {
			sLogger.Warn("parseMessage error, skipping")
			continue
		}

		if msgEdit, ok := msg.(*messageEdit); ok {
			ch := c.initWaitChan(msgEdit.id.String())
			go func(m *messageEdit, ch chan<- interface{}) {
				ch <- m
			}(msgEdit, ch)
		} else if msgMeta, ok := msg.(*messageMeta); ok {
			c.breakPointRules = msgMeta.breakPointRules
		} else {
			sLogger.Warn("invalid message, skipping")
		}
	}
}

func (c *concurrentConn) initWaitChan(key string) chan interface{} {
	c.waitChansMu.Lock()
	defer c.waitChansMu.Unlock()

	if ch, ok := c.waitChans[key]; ok {
		return ch
	}
	ch := make(chan interface{})
	c.waitChans[key] = ch
	return ch
}

// Determine if it should intercept.
func (c *concurrentConn) isIntercpt(f *proxy.Flow, after *messageFlow) bool {
	if after.mType != messageTypeRequestBody && after.mType != messageTypeResponseBody {
		return false
	}

	if len(c.breakPointRules) == 0 {
		return false
	}

	var action int
	if after.mType == messageTypeRequestBody {
		action = 1
	} else {
		action = 2
	}

	for _, rule := range c.breakPointRules {
		if rule.URL == "" {
			continue
		}
		if action&rule.Action == 0 {
			continue
		}
		if rule.Method != "" && rule.Method != f.Request.Method {
			continue
		}
		if strings.Contains(f.Request.URL.String(), rule.URL) {
			return true
		}
	}

	return false
}

// Intercept.
func (c *concurrentConn) waitIntercept(f *proxy.Flow, after *messageFlow) {
	ch := c.initWaitChan(f.Id.String())
	msg := (<-ch).(*messageEdit)

	// Drop.
	if msg.mType == messageTypeDropRequest || msg.mType == messageTypeDropResponse {
		f.Response = &proxy.Response{
			StatusCode: 502,
		}
		return
	}

	// change
	if msg.mType == messageTypeChangeRequest {
		f.Request.Method = msg.request.Method
		f.Request.URL = msg.request.URL
		f.Request.Header = msg.request.Header
		f.Request.Body = msg.request.Body
	} else if msg.mType == messageTypeChangeResponse {
		f.Response.StatusCode = msg.response.StatusCode
		f.Response.Header = msg.response.Header
		f.Response.Body = msg.response.Body
	}
}
