/**
 * Placeholders for the reports and qualification views, which another change provides
 * (src/routes/Reports*.tsx, src/routes/Qualification.tsx, src/components/evaluations/*,
 * src/lib/evaluation.ts). The integrator replaces these components and their routes.
 */
import { Card, CardContent } from "@/components/ui/card";

function Placeholder({ title, eyebrow }: { title: string; eyebrow: string }) {
  return (
    <div className="space-y-6">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
      </div>
      <Card>
        <CardContent className="empty">
          This view is not available in this build yet.
        </CardContent>
      </Card>
    </div>
  );
}

export const Reports = () => (
  <Placeholder title="Reports" eyebrow="Evaluation evidence" />
);
export const Qualification = () => (
  <Placeholder title="Qualification" eyebrow="Release evidence" />
);
