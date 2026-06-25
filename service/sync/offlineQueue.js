const { readJson, writeJson } = require('../storage/localStateStore');
const logger = require('../logging/serviceLogger');

/**
 * Durable, de-duplicated FIFO queue persisted to a JSON file. Used for both the
 * heartbeat and violation backlogs so that when the backend is unreachable
 * nothing is lost, and reconnection does not produce duplicate uploads.
 *
 * De-dup: every item carries an `id`; enqueuing an existing id is a no-op and
 * flushing removes an item only after a confirmed successful send.
 */
class OfflineQueue {
  /**
   * @param {string} filePath  where to persist
   * @param {number} maxItems  cap (oldest dropped beyond this)
   * @param {string} tag       log category
   */
  constructor(filePath, maxItems, tag) {
    this.filePath = filePath;
    this.maxItems = maxItems;
    this.tag = tag;
    this.items = readJson(filePath, []) || [];
    if (!Array.isArray(this.items)) this.items = [];
  }

  size() {
    return this.items.length;
  }

  persist() {
    try {
      writeJson(this.filePath, this.items);
    } catch (e) {
      logger.warn('SYNC', `Failed to persist ${this.tag} queue`, e.message);
    }
  }

  enqueue(item) {
    if (!item || !item.id) return;
    if (this.items.some((i) => i.id === item.id)) return; // de-dup
    this.items.push(item);
    if (this.items.length > this.maxItems) {
      this.items.splice(0, this.items.length - this.maxItems);
    }
    this.persist();
  }

  /**
   * Attempt to send each queued item in order. `sender(item)` must resolve to a
   * normalized backend result `{ ok, offline }`. Stops early on an offline error
   * (keeps the rest queued); drops items that succeed or fail permanently
   * (non-offline) so a poison item can't block the queue forever.
   * @returns {Promise<{flushed:number, remaining:number}>}
   */
  async flush(sender) {
    if (this.items.length === 0) return { flushed: 0, remaining: 0 };
    let flushed = 0;
    const survivors = [];
    let wentOffline = false;

    for (const item of this.items) {
      if (wentOffline) {
        survivors.push(item);
        continue;
      }
      try {
        const res = await sender(item);
        if (res.ok) {
          flushed += 1;
        } else if (res.offline) {
          wentOffline = true;
          survivors.push(item);
        } else {
          // Permanent failure (e.g. 400/401): drop so it can't wedge the queue.
          logger.warn('SYNC', `Dropping ${this.tag} item after permanent error`, {
            id: item.id,
            status: res.status,
            error: res.error,
          });
        }
      } catch (e) {
        wentOffline = true;
        survivors.push(item);
        logger.warn('SYNC', `Flush error for ${this.tag}`, e.message);
      }
    }

    this.items = survivors;
    this.persist();
    if (flushed > 0) {
      logger.info('SYNC', `Flushed ${flushed} ${this.tag} item(s)`, { remaining: survivors.length });
    }
    return { flushed, remaining: survivors.length };
  }
}

module.exports = { OfflineQueue };
