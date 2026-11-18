package main

import (
	"fmt"
	"sort"
)

// Item 195. y68: Electron has two planes and neither is the UA. The renderer
// plane is the "Electron Isolated Context" world that contextIsolation creates;
// the main-process plane is the --inspect port, which this item reports as
// unreachable rather than pretending to read it (no Node inspector client here).
// The UA is weakened on purpose: setUserAgent replaces it entirely, so a match is
// evidence, a miss is not proof.

func init() {
	registerOp(op{
		name:  "list_electron_targets",
		route: "Y",
		desc:  "list renderer contexts and classify Electron by the isolated-world name, with the UA as a weaker signal",
		needs: true,
		run:   opListElectronTargets,
	})
}

const electronWorldName = "Electron Isolated Context"

type electronContext struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Origin    string `json:"origin"`
	IsDefault bool   `json:"is_default"`
	Type      string `json:"type"`
}

type electronReport struct {
	Targets     []webTargetRow    `json:"targets"`
	Contexts    []electronContext `json:"contexts"`
	Isolated    bool              `json:"electron_isolated_world"`
	UA          string            `json:"user_agent"`
	UAelectron  string            `json:"ua_electron_version,omitempty"`
	Verdict     string            `json:"verdict"` // electron | possible | not-seen
	Attribution []string          `json:"attribution"`
	ProcessPane string            `json:"process_plane,omitempty"`
}

func opListElectronTargets(target string) (any, error) {
	ep, _, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	uaExpr := `navigator.userAgent`
	out, sk, err := webRun("list_electron_targets", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Runtime.enable"},
			{Method: "Runtime.evaluate", Params: map[string]any{"expression": uaExpr, "returnByValue": true}},
		},
		Collect: &webCollect{Ms: 500, Prefixes: []string{"Runtime.executionContextCreated"}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	// A failed Runtime.enable means no context event could ever arrive: an empty
	// context list would then be a claim of absence the probe never earned.
	if len(out.Steps) == 0 || !out.Steps[0].Ok {
		return nil, fmt.Errorf("cdp %s: Runtime.enable: %s (the target was not ready for a session)", ep, stepFailure(out.Steps, 0))
	}
	// Lists stay arrays even when empty: "contexts": null reads as a missing
	// field, and the digest of this op is a list of contexts.
	res := electronReport{Targets: out.Targets, Contexts: []electronContext{}, Attribution: []string{}}
	if res.Targets == nil {
		res.Targets = []webTargetRow{}
	}
	for _, e := range out.Events {
		if e.Method != "Runtime.executionContextCreated" {
			continue
		}
		ctx, _ := e.Params["context"].(map[string]any)
		if ctx == nil {
			continue
		}
		aux, _ := ctx["auxData"].(map[string]any)
		row := electronContext{
			ID:     int(num(ctx["id"])),
			Name:   str(ctx["name"]),
			Origin: str(ctx["origin"]),
			Type:   str(aux["type"]),
		}
		if def, ok := aux["isDefault"].(bool); ok {
			row.IsDefault = def
		}
		if row.Name == electronWorldName {
			res.Isolated = true
		}
		res.Contexts = append(res.Contexts, row)
	}
	if len(out.Steps) > 1 && out.Steps[1].Ok {
		res.UA = str(nested(out.Steps[1].Result, "result", "value"))
	}
	if m := electronUARe.FindStringSubmatch(res.UA); m != nil {
		res.UAelectron = m[1]
		res.Attribution = append(res.Attribution, "ua")
	}
	if res.Isolated {
		res.Attribution = append([]string{"runtime"}, res.Attribution...)
	}
	switch {
	case res.Isolated:
		res.Verdict = "electron"
		res.ProcessPane = fmt.Sprintf("--inspect (default 9229) carries the main process; this endpoint is the renderer on %s", ep)
	case res.UAelectron != "":
		res.Verdict = "possible"
		res.ProcessPane = "UA names Electron but no isolated world was seen: contextIsolation may be off, which is not proof either way"
	default:
		res.Verdict = "not-seen"
		res.ProcessPane = "no renderer signal; read 127.0.0.1:9229/json/list for the main-process plane"
	}
	sort.Slice(res.Contexts, func(i, j int) bool { return res.Contexts[i].ID < res.Contexts[j].ID })
	return res, nil
}
