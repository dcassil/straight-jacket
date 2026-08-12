export function buildSkillPolicy() {
  return {
    requiredFirstChecks: [
      "straight-jacket list --json",
      "straight-jacket verify --json"
    ],
    forbiddenActions: [
      "edit .straight-jacket/manifest.json",
      "edit .straight-jacket/manifest.sig",
      "edit .straight-jacket/public-key.json",
      "ask user for password in chat",
      "commit with --no-verify to bypass checks"
    ]
  };
}
