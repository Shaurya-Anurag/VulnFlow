# VulnFlow UI smoke checklist (manual, dependency-free)

Use this checklist after the frontend/API integration changes. There is no configured browser test runner, so these checks use the existing local API, Vite dev server, and a browser's built-in DevTools. No packages are needed.

## Setup

1. Use only a disposable local VulnFlow database. Set `VULNFLOW_DB_PATH` to a temporary path before starting the API; never point this checklist at production or a database containing user data.
2. Start FastAPI on `127.0.0.1:8000` and Vite on `127.0.0.1:5173` using the commands in the project README.
3. Open the Vite URL in a browser. Keep the browser console and Network panel available. The app's API data comes from `/api/dashboard`, `/api/findings`, `/api/activity`, and `/api/approvals`.

## Navigation and view state

- [ ] The persistent navigation contains Overview, Findings, Investigations, Remediation, Approvals, Agent Network, and Audit.
- [ ] Selecting each item changes the active view and marks the selected navigation item clearly; keyboard focus remains visible and navigation controls can be reached with Tab/Enter.
- [ ] Refreshing while on a view does not leave the UI stuck in a loading state or show an unrelated view as selected.
- [ ] A selected finding's detail is shown only when a finding is selected; an empty selection has an explicit instruction/empty state.

## Honest data and lifecycle

- [ ] Synthetic demo findings carry a visible “Synthetic demo” label and are distinct from real finding totals.
- [ ] Finding status filters and transition choices use exactly: reported, investigating, planned, patching, verifying, resolved, rejected. No old values such as open, triaged, accepted, remediated, false_positive, or closed appear as selectable statuses.
- [ ] The normal review path can be recorded as reported → investigating → planned → patching → verifying → resolved. The UI allows retry/reopen choices exposed by the workflow API, and a rejected finding is labeled rejected.
- [ ] Evidence and imported descriptions display as text. A harmless sample string such as `<b>sample</b>` remains visible as text and is not rendered as markup. Report paths and URIs do not trigger fetches or open automatically.
- [ ] Missing severity reasoning, agent assessment/disagreement, patch contents/history, or other unsupported fields are labeled “Not recorded”/“Not integrated” or shown as an honest empty state; they are not inferred from severity or finding status.

## Approvals and agent activity

- [ ] Approval action choices use only `propose_remediation`, `change_finding_state`, and `export_evidence` (friendly display labels are fine).
- [ ] An approval displays its exact action and parameters, requester, status/decision, approver, and decision reason when present.
- [ ] A proposal is requested by `vulnflow-remediation`; a human decision is recorded by `local-operator`. The UI keeps those identities distinct and shows pending/approved/rejected/expired states accurately.
- [ ] Approve/reject records a workflow decision only; it does not execute a patch, change a finding, export evidence, or trigger a scanner.
- [ ] Agent Network explicitly says live Switch connection/roster/activity is not integrated with this API. It shows only persisted agent activity returned by `/api/activity`; no fabricated online/offline status is shown. With no persisted activity, show “No activity recorded” or equivalent.

## Loading, empty, and error states

- [ ] On first load, a loading indicator is visible while requests are pending and clears after responses complete.
- [ ] Throttle localhost requests in DevTools, select Refresh, and confirm the loading state is visible and duplicate refresh is disabled or otherwise safely handled.
- [ ] Filter to a lifecycle state with no matching finding and confirm a clear no-results message. Empty approvals and activity also have explicit messages when their API lists are empty.
- [ ] With the API stopped, reload or select Refresh. Show a visible error/retry path; do not present the failed response as a genuine empty workspace.
- [ ] Restart the API and retry; the error clears when data loads successfully.

## Narrow responsive layout

- [ ] In DevTools device emulation, inspect widths of 320 px, 375 px, and 768 px. Navigation, summary cards, lists, detail, approval controls, and audit content remain readable and usable.
- [ ] At 320 px there is no page-level horizontal scrolling; long finding titles, paths, evidence, parameters, and activity text wrap or scroll within their own region.
- [ ] Buttons, selects, and text inputs remain visible, have usable touch targets, and do not overlap or clip behind fixed navigation.

## Record the check

Record the date, browser/version, tested API/UI revision, viewport widths, pass/fail per section, and any console/API errors. A failed item should include the view and a short reproduction path. Do not include sensitive imported evidence in screenshots or notes.
