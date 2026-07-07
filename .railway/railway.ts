import { defineRailway, github, preserve, project, service } from "railway/iac";

export default defineRailway(() => {
  const dailyPatchReport = github("hoiber/daily-patch-report");

  const _workspacecveDashboard = service("@workspace/cve-dashboard", {
    source: dailyPatchReport,
    build: { builder: "DOCKERFILE", dockerfilePath: "artifacts/cve-dashboard/Dockerfile" },
    replicas: 1,
    networking: { privateNetworkEndpoint: "workspacecve-dashboard" },
  });
  const _workspaceapiServer = service("@workspace/api-server", {
    source: dailyPatchReport,
    build: { builder: "DOCKERFILE", dockerfilePath: "artifacts/api-server/Dockerfile" },
    healthcheckPath: "/api/healthz",
    healthcheckTimeout: 30,
    replicas: 1,
    networking: { privateNetworkEndpoint: "workspaceapi-server" },
    env: {
      PORT: preserve(),
    },
  });

  return project("enthusiastic-unity", {
    resources: [_workspacecveDashboard, _workspaceapiServer],
  });
});
