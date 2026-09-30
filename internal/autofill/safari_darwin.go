package autofill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

type Safari struct{ window, tab int }

func OpenSafari(target string) (Browser, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 {
		return nil, errors.New("Safari target must be WINDOW_ID:TAB_INDEX (one based)")
	}
	w, e := strconv.Atoi(parts[0])
	t, e2 := strconv.Atoi(parts[1])
	if e != nil || e2 != nil || w < 1 || t < 1 {
		return nil, errors.New("invalid Safari target")
	}
	return &Safari{w, t}, nil
}
func SafariTargets(ctx context.Context) ([]Target, error) {
	var targets []Target
	e := safariScript(ctx, `const app=Application("Safari"); const out=[]; for(const w of app.windows()){let n=0;for(const t of w.tabs()){n++;let url;try{url=t.url()}catch{continue}out.push({id:String(w.id())+":"+n,title:t.name(),url,type:"page"})}} JSON.stringify(out);`, &targets)
	return targets, e
}
func safariScript(ctx context.Context, script string, out any) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-l", "JavaScript", "-")
	cmd.Stdin = strings.NewReader(script)
	var buffer bytes.Buffer
	cmd.Stdout = &buffer
	cmd.Stderr = nil
	if e := cmd.Run(); e != nil {
		return errors.New("Safari automation is unavailable; grant macOS Automation access and enable Safari JavaScript from Apple Events")
	}
	if buffer.Len() > 2*1024*1024 {
		return errors.New("Safari response too large")
	}
	if json.Unmarshal(buffer.Bytes(), out) != nil {
		return errors.New("invalid Safari automation response")
	}
	return nil
}
func (s *Safari) execute(ctx context.Context, action string, expected Inspection, values map[string]string, out any) error {
	a, _ := json.Marshal(action)
	e, _ := json.Marshal(expected)
	v, _ := json.Marshal(values)
	defer clear(v)
	js := "(()=>{" + pageScript + ";return JSON.stringify(vaultPage(" + string(a) + "," + string(e) + "," + string(v) + "));})()"
	encoded, _ := json.Marshal(js)
	defer clear(encoded)
	script := `const app=Application("Safari"); const w=app.windows.byId(` + strconv.Itoa(s.window) + `); const tab=w.tabs[` + strconv.Itoa(s.tab-1) + `]; app.doJavaScript(` + string(encoded) + `,{in:tab});`
	return safariScript(ctx, script, out)
}
func (s *Safari) Inspect(ctx context.Context) (Inspection, error) {
	var in Inspection
	e := s.execute(ctx, "inspect", Inspection{}, nil, &in)
	return in, e
}
func (s *Safari) Fill(ctx context.Context, in Inspection, values map[string]string) (int, error) {
	var result struct {
		Filled int `json:"filled"`
	}
	e := s.execute(ctx, "fill", in, values, &result)
	return result.Filled, e
}
func (s *Safari) Close() error { return nil }
