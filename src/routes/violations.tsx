import { createFileRoute } from "@tanstack/react-router";
import ViolationLog from "@/pages/ViolationLog";

export const Route = createFileRoute("/violations")({
  head: () => ({ meta: [{ title: "NetFast — Integrity Log" }] }),
  component: ViolationLog,
});
