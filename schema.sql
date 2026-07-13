-- ============================================================
-- SURD schema — run this once in Supabase SQL Editor
-- (Dashboard → SQL Editor → New query → paste all → Run)
-- ============================================================

-- Profiles: one row per signed-up user, mirrors auth.users
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default 'New User',
  handle text unique not null,
  color text default 'linear-gradient(135deg,#4D7CE8,#4DE8A0)',
  bio text default '',
  created_at timestamptz default now()
);

-- Posts
create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete cascade,
  text text default '',
  media_url text,
  media_type text, -- 'image' | 'video' | null
  created_at timestamptz default now()
);

-- Likes
create table if not exists public.likes (
  post_id uuid references public.posts(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete cascade,
  created_at timestamptz default now(),
  primary key (post_id, user_id)
);

-- Stories (24h expiring)
create table if not exists public.stories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete cascade,
  text text default '',
  media_url text,
  media_type text,
  created_at timestamptz default now()
);

-- Chats (1:1 for now)
create table if not exists public.chats (
  id uuid primary key default gen_random_uuid(),
  user_a uuid references public.profiles(id) on delete cascade,
  user_b uuid references public.profiles(id) on delete cascade,
  created_at timestamptz default now(),
  unique (user_a, user_b)
);

-- Messages
create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid references public.chats(id) on delete cascade,
  sender_id uuid references public.profiles(id) on delete cascade,
  text text default '',
  media_url text,
  media_type text,
  created_at timestamptz default now()
);

-- Reports (for admin panel)
create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  type text not null, -- 'post' | 'user' | 'message'
  target_id text not null,
  reason text,
  status text default 'open',
  created_at timestamptz default now()
);

-- Admins allowlist (simple: list of user ids who can see /admin)
create table if not exists public.admins (
  user_id uuid primary key references public.profiles(id) on delete cascade
);

-- ============================================================
-- Row Level Security
-- ============================================================
alter table public.profiles enable row level security;
alter table public.posts enable row level security;
alter table public.likes enable row level security;
alter table public.stories enable row level security;
alter table public.chats enable row level security;
alter table public.messages enable row level security;
alter table public.reports enable row level security;
alter table public.admins enable row level security;

-- Profiles: anyone logged in can read all profiles; only owner can update their own
create policy "profiles are viewable by everyone" on public.profiles for select using (true);
create policy "users can update own profile" on public.profiles for update using (auth.uid() = id);
create policy "users can insert own profile" on public.profiles for insert with check (auth.uid() = id);

-- Posts: everyone can read; only author can insert/delete their own
create policy "posts viewable by everyone" on public.posts for select using (true);
create policy "users insert own posts" on public.posts for insert with check (auth.uid() = user_id);
create policy "users delete own posts" on public.posts for delete using (auth.uid() = user_id);

-- Likes
create policy "likes viewable by everyone" on public.likes for select using (true);
create policy "users manage own likes" on public.likes for insert with check (auth.uid() = user_id);
create policy "users remove own likes" on public.likes for delete using (auth.uid() = user_id);

-- Stories
create policy "stories viewable by everyone" on public.stories for select using (true);
create policy "users insert own stories" on public.stories for insert with check (auth.uid() = user_id);
create policy "users delete own stories" on public.stories for delete using (auth.uid() = user_id);

-- Chats: only members can see their chat
create policy "members can view their chats" on public.chats for select
  using (auth.uid() = user_a or auth.uid() = user_b);
create policy "users can create chats they belong to" on public.chats for insert
  with check (auth.uid() = user_a or auth.uid() = user_b);

-- Messages: only chat members can read/write
create policy "members can view messages" on public.messages for select
  using (
    exists (
      select 1 from public.chats c
      where c.id = chat_id and (c.user_a = auth.uid() or c.user_b = auth.uid())
    )
  );
create policy "members can send messages" on public.messages for insert
  with check (
    auth.uid() = sender_id and
    exists (
      select 1 from public.chats c
      where c.id = chat_id and (c.user_a = auth.uid() or c.user_b = auth.uid())
    )
  );

-- Reports: any logged-in user can file; only admins can read/update
create policy "users can file reports" on public.reports for insert with check (auth.uid() is not null);
create policy "admins can view reports" on public.reports for select
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()));
create policy "admins can update reports" on public.reports for update
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()));

-- Admins table: only admins can see who else is admin
create policy "admins can view admin list" on public.admins for select
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()));

-- Admin override: let admins delete/moderate any post
create policy "admins can delete any post" on public.posts for delete
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()));

-- ============================================================
-- Auto-create a profile row when someone signs up
-- ============================================================
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, name, handle)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1)),
    coalesce(new.raw_user_meta_data->>'handle', '@' || split_part(new.email,'@',1) || substr(new.id::text,1,4))
  );
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ============================================================
-- Storage bucket policies (bucket must be named "media", created via dashboard)
-- ============================================================
create policy "media is publicly readable"
  on storage.objects for select
  using (bucket_id = 'media');

create policy "authenticated users can upload media"
  on storage.objects for insert
  with check (bucket_id = 'media' and auth.uid() is not null);

create policy "users can delete own media"
  on storage.objects for delete
  using (bucket_id = 'media' and owner = auth.uid());

-- ============================================================
-- To make yourself an admin after signing up, run (with your real user id):
-- insert into public.admins (user_id) values ('YOUR-USER-UUID-HERE');
-- You can find your user id in Authentication -> Users after you sign up.
-- ============================================================
