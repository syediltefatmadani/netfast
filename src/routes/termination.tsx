import { createFileRoute } from "@tanstack/react-router";
import Termination from "@/pages/Termination";

export const Route = createFileRoute("/termination")({
  head: () => ({ meta: [{ title: "NetFast — Challenge Ended" }] }),
  component: Termination,
});
