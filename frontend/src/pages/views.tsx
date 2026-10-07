import { useState } from "react";
import { Tabs } from "../components/ui";
import { Devices, Recipients } from "./Identity";
import { Forensics } from "./Forensics";
import { Investigations } from "./Investigations";
import { Incidents, RiskConsole, SecurityEvents } from "./Security";
import { Ledger, Nodes } from "./Ledger";
import { Audit, Intelligence, Revocations, SecurityLab, WatermarkProbe } from "./Ops";

type Tab = { id: string; label: string; needs: string[]; render: () => JSX.Element };

function visibleTabs(tabs: Tab[], permissions: string[]): Tab[] {
  return tabs.filter((t) => t.needs.some((p) => permissions.includes(p)));
}

function Hub({ tabs, permissions }: { tabs: Tab[]; permissions: string[] }) {
  const reachable = visibleTabs(tabs, permissions);
  const [picked, setPicked] = useState<string | null>(null);
  const active = reachable.find((t) => t.id === picked) ?? reachable[0];

  if (!active) return null;
  return (
    <>
      <Tabs tabs={reachable.map(({ id, label }) => ({ id, label }))} active={active.id} onPick={setPicked} />
      {active.render()}
    </>
  );
}

export function IdentityView({ permissions }: { permissions: string[] }) {
  return (
    <Hub
      permissions={permissions}
      tabs={[
        { id: "recipients", label: "Recipients", needs: ["recipient.create"], render: () => <Recipients /> },
        { id: "devices", label: "Devices", needs: ["device.manage"], render: () => <Devices /> },
      ]}
    />
  );
}

export function ForensicsView({ permissions }: { permissions: string[] }) {
  return (
    <Hub
      permissions={permissions}
      tabs={[
        { id: "verify", label: "Verification", needs: ["evidence.read", "forensics.analyze"], render: () => <Forensics /> },
        { id: "cases", label: "Investigations", needs: ["evidence.read", "case.manage"], render: () => <Investigations /> },
      ]}
    />
  );
}

export function SecurityView({ permissions }: { permissions: string[] }) {
  return (
    <Hub
      permissions={permissions}
      tabs={[
        { id: "events", label: "Events", needs: ["security.alert", "incident.manage"], render: () => <SecurityEvents /> },
        { id: "incidents", label: "Incidents", needs: ["incident.manage"], render: () => <Incidents /> },
        { id: "risk", label: "Risk", needs: ["incident.manage"], render: () => <RiskConsole /> },
      ]}
    />
  );
}

export function LedgerView({ permissions }: { permissions: string[] }) {
  return (
    <Hub
      permissions={permissions}
      tabs={[
        { id: "blocks", label: "Blocks & Transactions", needs: ["ledger.read"], render: () => <Ledger permissions={permissions} /> },
        { id: "nodes", label: "Nodes & Operations", needs: ["ledger.read", "ledger.admin"], render: () => <Nodes /> },
      ]}
    />
  );
}

export function OversightView({ permissions }: { permissions: string[] }) {
  return (
    <Hub
      permissions={permissions}
      tabs={[
        { id: "audit", label: "Audit Trail", needs: ["audit.read"], render: () => <Audit /> },
        { id: "revocations", label: "Revocations", needs: ["audit.read"], render: () => <Revocations /> },
        { id: "intelligence", label: "Intelligence", needs: ["ai.query", "commander.dashboard"], render: () => <Intelligence /> },
        { id: "lab", label: "Security Lab", needs: ["incident.manage"], render: () => <SecurityLab /> },
        { id: "watermark", label: "Watermark Probe", needs: ["evidence.read"], render: () => <WatermarkProbe /> },
      ]}
    />
  );
}
