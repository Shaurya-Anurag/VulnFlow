import { useCallback, useEffect, useState } from "react";
import {
  createApproval,
  decideApproval,
  importReport,
  loadDashboard,
  loadReviewBrief,
  runAgentWorkflow,
  verifyFindingWithVerityx,
  transitionFinding,
} from "./api";
import { VulnFlowShell } from "./components/VulnFlowShell";
import type { DashboardData, FindingStatus, ReviewBrief } from "./types";
import type { AgentWorkflowResult, VerityxVerificationResponse } from "./api";
import "./styles.css";

export function App() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reviewBrief, setReviewBrief] = useState<ReviewBrief | null>(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [agentWorkflow, setAgentWorkflow] = useState<AgentWorkflowResult | null>(null);
  const [agentWorkflowLoading, setAgentWorkflowLoading] = useState(false);
  const [verityxVerification, setVerityxVerification] = useState<VerityxVerificationResponse | null>(null);
  const [verityxLoading, setVerityxLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setData(await loadDashboard());
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load VulnFlow.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);


  const handleAnalyze = useCallback(async (findingId: string) => {
    setAnalysisLoading(true);
    setReviewBrief(null);
    try {
      setReviewBrief(await loadReviewBrief(findingId));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to prepare the review brief.");
    } finally {
      setAnalysisLoading(false);
    }
  }, []);

  const handleAgentWorkflow = useCallback(async (findingId: string) => {
    setAgentWorkflowLoading(true);
    setAgentWorkflow(null);
    try {
      setAgentWorkflow(await runAgentWorkflow(findingId));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The specialist-agent workflow failed.");
    } finally {
      setAgentWorkflowLoading(false);
    }
  }, []);


  const handleVerityxVerification = useCallback(async (findingId: string) => {
    setVerityxLoading(true);
    setVerityxVerification(null);
    try {
      const result = await verifyFindingWithVerityx(findingId);
      setVerityxVerification(result);
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Verityx verification failed.");
    } finally {
      setVerityxLoading(false);
    }
  }, [refresh]);

  const handleImport = useCallback(async (file: File) => {
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error("Choose a report smaller than 2 MiB.");
      const document: unknown = JSON.parse(await file.text());
      const format = file.name.toLowerCase().endsWith(".sarif") || file.name.toLowerCase().endsWith(".sarif.json")
        ? "sarif"
        : "json";
      await importReport(format, file.name, document);
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The report could not be imported.");
    }
  }, [refresh]);

  const handleTransition = useCallback(async (id: string, status: FindingStatus, reason: string) => {
    try {
      const finding = data?.findings.find((item) => item.id === id);
      if (!finding) return;
      await transitionFinding(id, status, reason, finding.version);
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The lifecycle update failed.");
    }
  }, [data, refresh]);

  const handleCreateApproval = useCallback(async (id: string, action: string) => {
    try {
      await createApproval(id, action);
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The approval request failed.");
    }
  }, [refresh]);

  const handleDecision = useCallback(async (id: string, decision: "approved" | "rejected", reason: string) => {
    try {
      await decideApproval(id, decision, reason);
      await refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The approval decision failed.");
    }
  }, [refresh]);

  return (
    <VulnFlowShell
      summary={data?.summary ?? null}
      findings={data?.findings ?? []}
      activities={data?.activities ?? []}
      approvals={data?.approvals ?? []}
      loading={loading}
      error={error}
      onRefresh={refresh}
      onImportFile={handleImport}
      onSelectFinding={() => setReviewBrief(null)}
      onAnalyzeFinding={handleAnalyze}
      reviewBrief={reviewBrief}
      analysisLoading={analysisLoading}
      onRunAgentWorkflow={handleAgentWorkflow}
      agentWorkflow={agentWorkflow}
      agentWorkflowLoading={agentWorkflowLoading}
      onVerifyWithVerityx={handleVerityxVerification}
      verityxVerification={verityxVerification}
      verityxLoading={verityxLoading}
      onTransition={handleTransition}
      onCreateApproval={handleCreateApproval}
      onDecideApproval={handleDecision}
    />
  );
}
