-- VisaPortal schema
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  email text,
  passport_number text,
  phone text,
  role text default 'client'
);
alter table public.profiles enable row level security;
create policy "profiles are viewable" on public.profiles for select using (true);
create policy "users update own profile" on public.profiles for update using (auth.uid() = id);

create table public.cases (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.profiles(id),
  title text,
  status text default 'new',
  consultant_notes text,
  created_at timestamptz default now()
);

create table public.documents (
  id uuid primary key default gen_random_uuid(),
  case_id uuid references public.cases(id),
  path text,
  file_name text,
  uploaded_at timestamptz default now()
);

create table public.payments (
  id uuid primary key default gen_random_uuid(),
  case_id uuid references public.cases(id),
  amount integer,
  status text
);

create view public.case_overview as
  select c.id, c.title, c.status, p.full_name, p.email, p.passport_number
  from public.cases c join public.profiles p on p.id = c.client_id;

insert into storage.buckets (id, name, public) values ('documents', 'documents', true);
