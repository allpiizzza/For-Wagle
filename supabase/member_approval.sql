-- =====================================================================
-- 와글 회원 승인 구조
-- Supabase 대시보드 → SQL Editor 에 통째로 붙여넣고 한 번 실행하세요.
-- (여러 번 실행해도 안전하게 작성되어 있어요)
-- =====================================================================

-- 1) 회원 테이블: 구글 로그인한 사람마다 한 줄씩 생겨요
create table if not exists public.members (
    id          uuid primary key references auth.users(id) on delete cascade,
    email       text,
    name        text,
    avatar_url  text,
    status      text not null default 'pending'
                check (status in ('pending', 'approved', 'rejected')),
    is_admin    boolean not null default false,
    created_at  timestamptz not null default now(),
    decided_at  timestamptz,
    decided_by  uuid references auth.users(id) on delete set null
);

alter table public.members enable row level security;

-- 2) 처음 로그인하면 자동으로 '승인 대기(pending)' 회원 생성
create or replace function public.handle_new_member()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
    insert into public.members (id, email, name, avatar_url)
    values (
        new.id,
        new.email,
        coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name'),
        coalesce(new.raw_user_meta_data->>'avatar_url', new.raw_user_meta_data->>'picture')
    )
    on conflict (id) do nothing;
    return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_member();

-- 이미 로그인해 본 사람들도 회원 테이블에 채워 넣기
insert into public.members (id, email, name, avatar_url)
select id,
       email,
       coalesce(raw_user_meta_data->>'full_name', raw_user_meta_data->>'name'),
       coalesce(raw_user_meta_data->>'avatar_url', raw_user_meta_data->>'picture')
from auth.users
on conflict (id) do nothing;

-- 3) 권한 확인용 함수 (다른 테이블 RLS 에서도 재사용 가능)
create or replace function public.is_admin()
returns boolean
language sql stable
security definer set search_path = public
as $$
    select exists (
        select 1 from public.members
        where id = auth.uid() and is_admin and status = 'approved'
    );
$$;

create or replace function public.is_approved()
returns boolean
language sql stable
security definer set search_path = public
as $$
    select exists (
        select 1 from public.members
        where id = auth.uid() and status = 'approved'
    );
$$;

-- 4) 읽기 권한: 본인 정보는 본인이, 전체 목록은 관리자만
drop policy if exists "members: 본인 또는 관리자 조회" on public.members;
create policy "members: 본인 또는 관리자 조회"
    on public.members for select
    to authenticated
    using (id = auth.uid() or public.is_admin());

-- 쓰기(insert/update/delete) 정책은 일부러 만들지 않아요.
-- → 회원이 스스로 status 를 바꿔 '셀프 승인' 하는 것을 막아요.
-- → 상태 변경은 아래 관리자 전용 함수로만 가능해요.

-- 5) 관리자 전용: 회원 상태 변경 (승인 / 거절 / 대기로 되돌리기)
create or replace function public.set_member_status(target uuid, new_status text)
returns void
language plpgsql
security definer set search_path = public
as $$
begin
    if not public.is_admin() then
        raise exception '관리자만 할 수 있어요';
    end if;
    if new_status not in ('pending', 'approved', 'rejected') then
        raise exception '잘못된 상태값: %', new_status;
    end if;
    if target = auth.uid() then
        raise exception '본인 상태는 바꿀 수 없어요';
    end if;

    update public.members
       set status     = new_status,
           decided_at = case when new_status = 'pending' then null else now() end,
           decided_by = case when new_status = 'pending' then null else auth.uid() end
     where id = target;
end;
$$;

-- 6) 관리자 전용: 다른 회원을 관리자로 지정 / 해제
create or replace function public.set_member_admin(target uuid, make_admin boolean)
returns void
language plpgsql
security definer set search_path = public
as $$
begin
    if not public.is_admin() then
        raise exception '관리자만 할 수 있어요';
    end if;
    if target = auth.uid() then
        raise exception '본인 권한은 바꿀 수 없어요';
    end if;

    update public.members
       set is_admin = make_admin,
           status   = case when make_admin then 'approved' else status end
     where id = target;
end;
$$;

revoke all on function public.set_member_status(uuid, text) from public, anon;
revoke all on function public.set_member_admin(uuid, boolean) from public, anon;
grant execute on function public.set_member_status(uuid, text) to authenticated;
grant execute on function public.set_member_admin(uuid, boolean) to authenticated;

-- =====================================================================
-- 7) 첫 관리자 지정 (최초 1회)
--    main.html 에서 본인 구글 계정으로 한 번 로그인한 뒤,
--    아래 이메일을 본인 것으로 바꿔서 이 줄만 따로 실행하세요.
-- =====================================================================
-- update public.members set status = 'approved', is_admin = true
--  where email = 'your-email@gmail.com';
