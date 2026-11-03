-- WorkTime UK: private names attached to invitations.

ALTER TABLE public.wt_friend_invites
ADD COLUMN IF NOT EXISTS friend_label text
CHECK (
  friend_label IS NULL OR
  length(trim(friend_label)) BETWEEN 1 AND 50
);

-- Only the sender can see their invitation label,
-- using the existing invitation RLS policy.

-- Automatically save the sender's private friend name
-- when the invited user accepts the invitation.

CREATE OR REPLACE FUNCTION public.wt_save_accepted_friend_name()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NEW.accepted_at IS NOT NULL
     AND OLD.accepted_at IS NULL
     AND NEW.accepted_by IS NOT NULL
     AND NEW.friend_label IS NOT NULL THEN

    INSERT INTO public.wt_friend_names
      (owner_id, friend_id, display_name)
    VALUES
      (NEW.sender_id, NEW.accepted_by, NEW.friend_label)
    ON CONFLICT (owner_id, friend_id) DO NOTHING;

  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.wt_save_accepted_friend_name()
FROM PUBLIC, anon, authenticated;

CREATE TRIGGER wt_invite_save_friend_name
AFTER UPDATE OF accepted_at ON public.wt_friend_invites
FOR EACH ROW
EXECUTE FUNCTION public.wt_save_accepted_friend_name();

-- Create an invitation with the sender's private friend name.
-- The original invitation function remains available.

CREATE FUNCTION public.wt_create_named_friend_invite(p_friend_name text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_user uuid := (SELECT auth.uid());
  v_token uuid;
  v_name text := trim(p_friend_name);
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Login required';
  END IF;

  IF v_name IS NULL OR length(v_name) NOT BETWEEN 1 AND 50 THEN
    RAISE EXCEPTION 'Friend name must contain 1 to 50 characters';
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(v_user::text, 0)
  );

  IF (
    SELECT count(*)
    FROM public.wt_friend_invites
    WHERE sender_id = v_user
      AND accepted_at IS NULL
      AND revoked_at IS NULL
      AND expires_at > now()
  ) >= 20 THEN
    RAISE EXCEPTION 'Active invitation limit reached';
  END IF;

  INSERT INTO public.wt_friend_invites(sender_id, friend_label)
  VALUES (v_user, v_name)
  RETURNING token INTO v_token;

  RETURN v_token;
END;
$$;

REVOKE ALL ON FUNCTION public.wt_create_named_friend_invite(text)
FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION public.wt_create_named_friend_invite(text)
TO authenticated;

-- Default to private, explicitly selected viewers for new accounts.
ALTER TABLE public.wt_share_settings ALTER COLUMN mode SET DEFAULT 'selected';
