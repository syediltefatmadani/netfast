import { useEffect, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './ui/dialog';
import { Button } from './ui/button';

function formatCountdown(ms) {
  if (ms <= 0) return '0:00:00';
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  return `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

export default function VpnWarningModal({
  open,
  msRemaining,
  reapplyLoading,
  reapplyError,
  onAcknowledgeAndReapply,
}) {
  const [displayMs, setDisplayMs] = useState(msRemaining ?? 0);

  useEffect(() => {
    setDisplayMs(msRemaining ?? 0);
  }, [msRemaining]);

  useEffect(() => {
    if (!open) return;
    const id = setInterval(() => {
      setDisplayMs((prev) => Math.max(0, prev - 1000));
    }, 1000);
    return () => clearInterval(id);
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={() => {}}>
      <DialogContent
        className="sm:max-w-lg bg-[#12121a] border-[#ef4444]/40 text-zinc-200"
        onPointerDownOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-[#ef4444] text-xl">
            <ShieldAlert className="w-5 h-5" />
            VPN Detected
          </DialogTitle>
          <DialogDescription asChild>
            <div className="space-y-4 text-sm text-zinc-300 text-left pt-2">
              <p>
                NetFast detected a VPN/proxy tunnel. This is treated as a bypass attempt. This is
                your first and final warning.
              </p>
              <p>
                Disable the VPN and re-apply protection within 24 hours to continue your challenge.
              </p>
              <p className="text-zinc-400">
                If you do not re-apply protection within 24 hours, your challenge will fail and your
                payment/deposit will not be refunded according to the challenge rules.
              </p>
              <p className="text-zinc-400">
                Another VPN/proxy attempt will immediately fail your challenge.
              </p>
              <p className="text-center font-mono text-lg text-[#fbbf24] tabular-nums">
                Time remaining: {formatCountdown(displayMs)}
              </p>
            </div>
          </DialogDescription>
        </DialogHeader>

        {reapplyError && (
          <p className="text-sm text-[#ef4444] bg-[#ef4444]/10 border border-[#ef4444]/30 rounded-lg px-3 py-2">
            {reapplyError}
          </p>
        )}

        <DialogFooter className="flex flex-col gap-2 sm:flex-col">
          <Button
            className="w-full bg-[#6c47ff] hover:bg-[#5a38e0] text-white"
            disabled={reapplyLoading}
            onClick={onAcknowledgeAndReapply}
          >
            {reapplyLoading ? 'Re-applying protection…' : 'I understand — Re-apply protection'}
          </Button>
          <p className="text-xs text-center text-zinc-500">
            Protection will only be re-applied after you disable the VPN.
          </p>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
