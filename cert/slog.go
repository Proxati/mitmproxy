package cert

import "log/slog"

var sLogger = slog.Default().WithGroup("mitmproxy.cert")
