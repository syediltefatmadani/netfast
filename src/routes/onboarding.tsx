import { createFileRoute } from "@tanstack/react-router";
import Onboarding from "@/pages/Onboarding";

export const Route = createFileRoute("/onboarding")({
  head: () => ({ meta: [{ title: "NetFast — Begin" }] }),
  component: Onboarding,
});
