package main

import "fmt"

func init() {
	registerOp(op{
		name:  "update_analysis_settings",
		route: "L",
		needs: false,
		desc:  "Update deep/maxBytes/minString in <state>/config.json; unset job fields keep their previous value, and values that cannot be read are rejected.",
		run:   runUpdateAnalysisSettings,
	})
}

func runUpdateAnalysisSettings(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	if job.Deep == nil && job.MaxBytes == nil && job.MinString == nil {
		return nil, fmt.Errorf("update_analysis_settings: job needs at least one of \"deep\", \"maxBytes\", \"minString\"")
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
	if !exists {
		st = metaSettingsDefault()
	}
	before := st
	if job.Deep != nil {
		st.Deep = *job.Deep
	}
	if job.MaxBytes != nil {
		if *job.MaxBytes <= 0 || *job.MaxBytes > 1<<30 {
			return nil, fmt.Errorf("update_analysis_settings: maxBytes %d is not inside 1..%d", *job.MaxBytes, 1<<30)
		}
		st.MaxBytes = *job.MaxBytes
	}
	if job.MinString != nil {
		if *job.MinString < 1 || *job.MinString > 64 {
			return nil, fmt.Errorf("update_analysis_settings: minString %d is not inside 1..64", *job.MinString)
		}
		st.MinString = *job.MinString
	}
	st.Kind = metaSettingsKind
	st.Updated = metaNow()
	if err := metaWriteJSON(file, st); err != nil {
		return nil, err
	}
	return map[string]any{
		"settings":    st,
		"before":      before,
		"config_file": file,
	}, nil
}
