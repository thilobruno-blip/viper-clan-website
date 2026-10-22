
create extension if not exists pgcrypto;

create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'member'
    check (role in ('owner','dev','admin','moderator','member')),
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  message text not null check (char_length(message) between 1 and 2000),
  created_at timestamptz not null default now()
);

create table if not exists public.role_applications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  requested_role text not null
    check (requested_role in ('owner','dev','admin','moderator')),
  message text not null check (char_length(message) between 1 and 2000),
  status text not null default 'pending'
    check (status in ('pending','approved','rejected')),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

create or replace function public.is_primary_owner()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from auth.users u
    where u.id = (select auth.uid())
      and lower(u.email) = lower('thilobruno@gmail.com')
  );
$$;

create or replace function public.has_role(roles text[])
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.user_roles r
    where r.user_id = (select auth.uid())
      and r.role = any(roles)
  );
$$;

revoke all on function public.is_primary_owner() from public;
revoke all on function public.has_role(text[]) from public;
grant execute on function public.is_primary_owner() to authenticated;
grant execute on function public.has_role(text[]) to authenticated;

alter table public.user_roles enable row level security;
alter table public.messages enable row level security;
alter table public.role_applications enable row level security;

create policy "Read own role or primary owner"
on public.user_roles for select to authenticated
using (user_id = (select auth.uid()) or public.is_primary_owner());

create policy "Primary owner inserts roles"
on public.user_roles for insert to authenticated
with check (public.is_primary_owner());

create policy "Primary owner updates roles"
on public.user_roles for update to authenticated
using (public.is_primary_owner())
with check (public.is_primary_owner());

create policy "Primary owner deletes roles"
on public.user_roles for delete to authenticated
using (public.is_primary_owner());

create policy "Members submit own messages"
on public.messages for insert to authenticated
with check (user_id = (select auth.uid()));

create policy "Admins and owner read messages"
on public.messages for select to authenticated
using (public.has_role(array['admin','owner']));

create policy "Admins and owner delete messages"
on public.messages for delete to authenticated
using (public.has_role(array['admin','owner']));

create policy "Members submit applications"
on public.role_applications for insert to authenticated
with check (
  user_id = (select auth.uid())
  and status = 'pending'
  and reviewed_by is null
  and reviewed_at is null
);

create policy "Read own applications or staff"
on public.role_applications for select to authenticated
using (
  user_id = (select auth.uid())
  or public.has_role(array['admin','owner'])
);

create policy "Only primary owner reviews applications"
on public.role_applications for update to authenticated
using (public.is_primary_owner())
with check (public.is_primary_owner());

-- First sign in to the website using Google with thilobruno@gmail.com.
-- Then run this statement in the Supabase SQL Editor:
insert into public.user_roles (user_id, role)
select id, 'owner'
from auth.users
where lower(email) = lower('thilobruno@gmail.com')
on conflict (user_id) do update
set role = 'owner', updated_at = now();
