package main

// metaSettings is `config.json`: the three scan knobs every reader understands.
type metaSettings struct {
	Kind      string `json:"kind"`
	Deep      bool   `json:"deep"`
	MaxBytes  int    `json:"maxBytes"`
	MinString int    `json:"minString"`
	Updated   string `json:"updated"`
}

const metaSettingsKind = "lrecon.config/1"

// metaSettingsDefault is the uncovered read budget: 8 MiB scanned, strings of
// four or more bytes. Stated in the result so a caller never guesses.
func metaSettingsDefault() metaSettings {
	return metaSettings{Kind: metaSettingsKind, MaxBytes: 8 << 20, MinString: 4}
}

func init() {
	registerOp(op{
		name:  "inspect_analysis_settings",
		route: "L",
		needs: false,
		desc:  "Show the analysis settings (deep, maxBytes, minString) from <state>/config.json, stating \"defaults\" when no file exists.",
		run:   runInspectAnalysisSettings,
	})
}

func runInspectAnalysisSettings(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	root, err := metaStateRoot(path, job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "config.json")
	if err != nil {
		return nil, err
	}
	st := metaSettingsDefault()
	exists, err := metaReadState(file, metaSettingsKind, &st)
	if err != nil {
		return nil, err
	}
	source := "defaults"
	if exists {
		source = "config"
	}
	return map[string]any{
		"settings":    st,
		"source":      source,
		"config_file": file,
	}, nil
}
