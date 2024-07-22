package web

import "log/slog"

var sLogger = slog.Default().WithGroup("mitmproxy.web")
