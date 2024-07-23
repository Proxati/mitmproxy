package proxy

import "log/slog"

var sLogger = slog.Default().WithGroup("mitmproxy.proxy")
