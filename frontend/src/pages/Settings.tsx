import { useState } from "react";
import { PageHead, Panel, Field, Notice } from "../components/ui";

export function SettingsView() {
  const [apiKey, setApiKey] = useState("");

  return (
    <div className="stack">
      <PageHead
        title="Settings"
        sub="Console preferences, session policy and operational mode. Changes apply locally to this terminal."
      />

      <Panel title="Appearance">
        <Field label="Theme">
          <select
            className="inp"
            defaultValue={localStorage.getItem("sentinel-theme") ?? "light"}
            onChange={(e) => localStorage.setItem("sentinel-theme", e.target.value)}
          >
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </Field>
        <Field label="Density">
          <select className="inp">
            <option value="compact">Compact</option>
            <option value="comfortable" selected>
              Comfortable
            </option>
          </select>
        </Field>
      </Panel>

      <Panel title="API access">
        <Field label="API key">
          <input
            className="inp"
            type="password"
            placeholder="sk_live_…"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
          />
        </Field>
        <button
          className="btn"
          onClick={() => {
            // No-op in prototype: tokens are issued by the back-end only.
            console.log("API key would be rotated via the command backend");
          }}
        >
          Rotate key
        </button>
      </Panel>

      <Notice tone="warn">
        <b>Prototype limitation</b>
        Settings are local-only in this build. Authentication and key rotation are controlled by the back-end token service.
      </Notice>
    </div>
  );
}
