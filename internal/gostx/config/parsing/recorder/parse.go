package recorder

import (
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/greyhavenhq/greyproxy/internal/gostcore/logger"
	"github.com/greyhavenhq/greyproxy/internal/gostcore/recorder"
	"github.com/greyhavenhq/greyproxy/internal/gostx/config"
	xrecorder "github.com/greyhavenhq/greyproxy/internal/gostx/recorder"
	"gopkg.in/natefinch/lumberjack.v2"
)

type discardCloser struct{}

func (discardCloser) Write(p []byte) (n int, err error) { return len(p), nil }
func (discardCloser) Close() error                      { return nil }

func ParseRecorder(cfg *config.RecorderConfig) (r recorder.Recorder) {
	if cfg == nil {
		return nil
	}

	// gRPC/HTTP plugin support removed

	if cfg.File != nil && cfg.File.Path != "" {
		var out io.WriteCloser = discardCloser{}

		if cfg.File.Rotation != nil {
			out = &lumberjack.Logger{
				Filename:   cfg.File.Path,
				MaxSize:    cfg.File.Rotation.MaxSize,
				MaxAge:     cfg.File.Rotation.MaxAge,
				MaxBackups: cfg.File.Rotation.MaxBackups,
				LocalTime:  cfg.File.Rotation.LocalTime,
				Compress:   cfg.File.Rotation.Compress,
			}
		} else {
			os.MkdirAll(filepath.Dir(cfg.File.Path), 0755)
			f, err := os.OpenFile(cfg.File.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				logger.Default().Warn(err)
			} else {
				out = f
			}
		}

		return xrecorder.FileRecorder(out,
			xrecorder.RecorderFileRecorderOption(cfg.Name),
			xrecorder.SepFileRecorderOption(cfg.File.Sep),
		)
	}

	if cfg.TCP != nil && cfg.TCP.Addr != "" {
		return xrecorder.TCPRecorder(cfg.TCP.Addr,
			xrecorder.RecorderTCPRecorderOption(cfg.Name),
			xrecorder.TimeoutTCPRecorderOption(cfg.TCP.Timeout),
		)
	}

	if cfg.HTTP != nil && cfg.HTTP.URL != "" {
		h := http.Header{}
		for k, v := range cfg.HTTP.Header {
			h.Add(k, v)
		}
		return xrecorder.HTTPRecorder(cfg.HTTP.URL,
			xrecorder.RecorderHTTPRecorderOption(cfg.Name),
			xrecorder.TimeoutHTTPRecorderOption(cfg.HTTP.Timeout),
			xrecorder.HeaderHTTPRecorderOption(h),
		)
	}

	return
}
