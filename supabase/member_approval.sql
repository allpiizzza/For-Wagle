-- =====================================================================
-- 와글 회원 승인 구조
-- Supabase 대시보드 → SQL Editor 에 통째로 붙여넣고 한 번 실행하세요.
-- (여러 번 실행해도 안전하고, 예전 is_admin 버전을 이미 실행했어도 그대로 옮겨져요)
--
-- auth_level (숫자가 작을수록 권한이 높아요)
--   0 = 관리자     회원 승인·거절, 등급 변경
--   1 = 이벤트팀
--   2 = 일반 팀원
--   3 = 신입       (처음 가입하면 기본값)
-- =====================================================================

-- 1) 회원 테이블
create table if not exists public.members (
    id          uuid primary key references auth.users(id) on delete cascade,
    email       text,
    name        text,
    avatar_url  text,
    status      text not null default 'pending'
                check (status in ('pending', 'approved', 'rejected')),
    auth_level  smallint not null default 3
                check (auth_level between 0 and 3),
    created_at  timestamptz not null default now(),
    decided_at  timestamptz,
    decided_by  uuid references auth.users(id) on delete set null
);

-- 예전 버전(is_admin 컬럼)을 이미 실행한 경우: auth_level 로 옮기고 is_admin 삭제
alter table public.members
    add column if not exists auth_level smallint not null default 3
    check (auth_level between 0 and 3);

do $$
begin
    if exists (
        select 1 from information_schema.columns
        where table_schema = 'public' and table_name = 'members' and column_name = 'is_admin'
    ) then
        execute 'update public.members set auth_level = 0 where is_admin';
        execute 'alter table public.members drop column is_admin';
    end if;
end;
$$;

drop function if exists public.set_member_admin(uuid, boolean);

comment on column public.members.auth_level is '0=관리자, 1=이벤트팀, 2=일반 팀원, 3=신입';

alter table public.members enable row level security;

-- 2) 구글로 처음 로그인하면 '승인 대기 + 신입(3)' 회원 자동 생성
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

-- 이미 로그인해 본 계정도 회원 테이블에 채워 넣기
insert into public.members (id, email, name, avatar_url)
select id,
       email,
       coalesce(raw_user_meta_data->>'full_name', raw_user_meta_data->>'name'),
       coalesce(raw_user_meta_data->>'avatar_url', raw_user_meta_data->>'picture')
from auth.users
on conflict (id) do nothing;

-- 3) 권한 확인 함수 (다른 테이블 RLS 에서도 재사용 가능)

-- 승인된 회원 중 등급이 max_level 이하인지
--   예) has_level(1) → 관리자·이벤트팀만 true
create or replace function public.has_level(max_level int)
returns boolean
language sql stable
security definer set search_path = public
as $$
    select exists (
        select 1 from public.members
        where id = auth.uid() and status = 'approved' and auth_level <= max_level
    );
$$;

create or replace function public.is_admin()
returns boolean
language sql stable
security definer set search_path = public
as $$
    select public.has_level(0);
$$;

create or replace function public.is_approved()
returns boolean
language sql stable
security definer set search_path = public
as $$
    select public.has_level(3);
$$;

-- 4) 조회 규칙: 본인 줄은 본인이, 전체는 관리자만
drop policy if exists "members: 본인 또는 관리자 조회" on public.members;
create policy "members: 본인 또는 관리자 조회"
    on public.members for select
    to authenticated
    using (id = auth.uid() or public.is_admin());

-- 추가/수정/삭제 규칙은 일부러 없음 → 회원이 스스로 승인하거나 등급을 올릴 수 없음
-- 상태·등급 변경은 아래 관리자 전용 함수로만 가능

-- 5) 관리자 전용: 승인 / 거절 / 대기로 되돌리기
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

-- 6) 관리자 전용: 등급 변경 (0=관리자, 1=이벤트팀, 2=일반 팀원, 3=신입)
create or replace function public.set_member_level(target uuid, new_level int)
returns void
language plpgsql
security definer set search_path = public
as $$
begin
    if not public.is_admin() then
        raise exception '관리자만 할 수 있어요';
    end if;
    if new_level not between 0 and 3 then
        raise exception '잘못된 등급: %', new_level;
    end if;
    if target = auth.uid() then
        raise exception '본인 등급은 바꿀 수 없어요';
    end if;

    update public.members
       set auth_level = new_level
     where id = target;
end;
$$;

revoke all on function public.set_member_status(uuid, text) from public, anon;
revoke all on function public.set_member_level(uuid, int) from public, anon;
grant execute on function public.set_member_status(uuid, text) to authenticated;
grant execute on function public.set_member_level(uuid, int) to authenticated;

-- =====================================================================
-- 7) 첫 관리자 지정 (최초 1회)
--    main.html 에서 본인 구글 계정으로 한 번 로그인한 뒤,
--    아래 이메일을 본인 것으로 바꿔서 이 줄만 따로 실행하세요.
-- =====================================================================
-- update public.members set status = 'approved', auth_level = 0
--  where email = 'your-email@gmail.com';
