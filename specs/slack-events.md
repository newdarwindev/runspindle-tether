# Tether integration contract

Extend the existing Tether/RepoFleet integration instead of introducing a new Slack subsystem or Slack Bolt. Preserve exact message/thread/event identity, sender authority and task/native-session attribution. Sanitize emitted events before transmission. Duplicate/retry/edit/delete reconciliation must use a fake Slack transport in public tests.

Existing guarded CLI forwarding is final-output oriented. All-session live mirroring is not established. Mirror only supported exposed runtime events. Delivery accepted, delivered, failed and unknown are separate states; unknown delivery must be reconciled before retry.

Legacy evidence and implementation import remain pending review. Preserve historical limitations and distinguish them from new acceptance results.
