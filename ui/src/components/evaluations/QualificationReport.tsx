import { shortHash, type QualificationReport } from "@/lib/reports";
import { Field, Section, StatusBadge } from "./common";

// The checks `qualify_runtime` records per profile, in execution order.
const CHECK_ORDER = [
  "boundary",
  "roundtrip",
  "saved_operation",
  "sandbox_reuse",
  "cleanup",
];
const CHECK_LABELS: Record<string, string> = {
  boundary: "Boundary",
  roundtrip: "Roundtrip",
  saved_operation: "Saved operation",
  sandbox_reuse: "Sandbox reuse",
  cleanup: "Cleanup",
};

/**
 * Native OpenShell qualification: real workspace and probe sandboxes through the production
 * adapter, with no model calls. Model quality is therefore always outside its scope.
 */
export function QualificationReportView({
  report,
}: {
  report: QualificationReport;
}) {
  const checks = [
    ...CHECK_ORDER,
    ...[
      ...new Set(
        report.profiles.flatMap((profile) => Object.keys(profile.checks)),
      ),
    ].filter((key) => !CHECK_ORDER.includes(key)),
  ];
  return (
    <div className="space-y-6">
      <Section
        title="Native boundary qualification"
        description="Exercises real workspace and probe sandboxes through the production adapter. It sends no model requests, so it says nothing about model quality."
        action={<StatusBadge status={report.status} />}
      >
        <dl className="grid grid-cols-2 gap-4 text-sm md:grid-cols-3">
          <Field
            label="Run ID"
            mono
            copy={{ value: report.run_id, label: "Copy run ID" }}
          >
            {report.run_id ?? "Unavailable"}
          </Field>
          <Field
            label="OpenShell config"
            mono
            copy={{
              value: report.config_sha256,
              label: "Copy OpenShell config SHA-256",
            }}
          >
            {shortHash(report.config_sha256, 16) ?? "Unavailable"}
          </Field>
          <Field label="Run cleanup">
            <StatusBadge status={report.cleanup ?? "not_checked"} />
            {report.cleanup_error_type && (
              <span className="ml-2 font-mono text-xs">
                {report.cleanup_error_type}
              </span>
            )}
          </Field>
          <Field label="Model calls">
            {report.model_calls == null ? "Unavailable" : report.model_calls}
          </Field>
          <Field label="Model quality">
            <StatusBadge status={report.model_quality ?? "not_checked"} />
          </Field>
          {report.error_type && (
            <Field label="Stopped with" mono>
              {report.error_type}
            </Field>
          )}
        </dl>
      </Section>
      <Section
        title="Profiles"
        description="A check left not checked was never reached: an earlier step failed or the run stopped."
      >
        {report.profiles.length ? (
          <div className="relative overflow-auto">
            <table className="data-table">
              <caption className="sr-only">
                Qualification checks by sandbox profile
              </caption>
              <thead>
                <tr>
                  <th scope="col">Profile</th>
                  {checks.map((check) => (
                    <th key={check} scope="col">
                      {CHECK_LABELS[check] ?? check.replaceAll("_", " ")}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.profiles.map((profile) => (
                  <tr key={profile.name}>
                    <th
                      scope="row"
                      className="font-mono font-medium text-foreground"
                    >
                      {profile.name}
                    </th>
                    {checks.map((check) => (
                      <td key={check}>
                        <StatusBadge
                          status={profile.checks[check] ?? "not_checked"}
                        />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="empty">No profile was qualified in this run.</p>
        )}
      </Section>
    </div>
  );
}
