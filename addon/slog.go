package addon

import "log/slog"

var sLogger = slog.Default().WithGroup("mitmproxy.addon")
