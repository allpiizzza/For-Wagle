-- =====================================================================
-- 와글 회원 승인 구조 (화면에서 insert / update 하는 버전)
-- Supabase 대시보드 → SQL Editor 에 통째로 붙여넣고 한 번 실행하세요.
-- 여러 번 실행해도 안전하고, 예전 버전(트리거·함수 방식, is_admin 컬럼)을
-- 이미 실행했어도 이 버전으로 정리돼요.
--
-- auth_level (숫자가 작을수록 권한이 높아요)
--   0 = 관리자     회원 승인·거절, 등급 변경
--   1 = 이벤트팀
--   2 = 일반 팀원
--   3 = 신입       (처음 가입하면 기본값)
--
-- 누가 무엇을 할 수 있나
--   - 로그인한 사람: 자기 회원 줄을 '승인 대기 + 신입' 으로만 insert 가능
--   - 회원: 자기 줄만 조회
--   - 관리자(0): 전체 조회, 다른 회원의 status / auth_level update
--   - 관리자도 자기 status / auth_level 은 못 바꿈 (실수로 권한 잃는 것 방지)
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

comment on column public.members.auth_level is '0=관리자, 1=이벤트팀, 2=일반 팀원, 3=신입';

-- 예전 버전의 자동 생성 트리거와 관리자 함수 정리 (이제 화면에서 직접 씀)
drop trigger if exists on_auth_user_created on auth.users;
drop function if exists public.handle_new_member();
drop function if exists public.set_member_admin(uuid, boolean);
drop function if exists public.set_member_status(uuid, text);
drop function if exists public.set_member_level(uuid, int);

alter table public.members enable row level security;

-- 2) 권한 확인 함수 (아래 규칙과 다른 테이블 RLS 에서 재사용)

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

-- 3) 테이블 권한 (실제 허용 범위는 아래 RLS 규칙이 정해요)
grant select, insert, update on public.members to authenticated;
revoke delete on public.members from authenticated, anon;
revoke all on public.members from anon;

-- 4) RLS 규칙
drop policy if exists "members: 본인 또는 관리자 조회" on public.members;
create policy "members: 본인 또는 관리자 조회"
    on public.members for select
    to authenticated
    using (id = auth.uid() or public.is_admin());

-- 본인 줄만, '승인 대기 + 신입' 으로만, 로그인한 구글 이메일 그대로만 insert 가능
drop policy if exists "members: 본인 가입 신청" on public.members;
create policy "members: 본인 가입 신청"
    on public.members for insert
    to authenticated
    with check (
        id = auth.uid()
        and status = 'pending'
        and auth_level = 3
        and decided_at is null
        and decided_by is null
        and email = (auth.jwt() ->> 'email')
    );

-- 관리자만 update 가능
drop policy if exists "members: 관리자 수정" on public.members;
create policy "members: 관리자 수정"
    on public.members for update
    to authenticated
    using (public.is_admin())
    with check (public.is_admin());

-- 5) update 검사 트리거
--    - 관리자가 자기 status / auth_level 을 바꾸는 것 차단
--    - id, created_at 은 못 바꿈
--    - status 가 바뀌면 decided_at / decided_by 자동 기록
--    (SQL Editor 에서 직접 실행할 때는 auth.uid() 가 없어서 자기 자신 검사는 건너뜀)
create or replace function public.guard_member_update()
returns trigger
language plpgsql
set search_path = public
as $$
begin
    if new.id <> old.id or new.created_at <> old.created_at then
        raise exception 'id, created_at 은 바꿀 수 없어요';
    end if;

    if old.id = auth.uid()
       and (new.status <> old.status or new.auth_level <> old.auth_level) then
        raise exception '본인 상태나 등급은 바꿀 수 없어요';
    end if;

    if new.status <> old.status then
        if new.status = 'pending' then
            new.decided_at := null;
            new.decided_by := null;
        else
            new.decided_at := now();
            new.decided_by := auth.uid();
        end if;
    end if;

    return new;
end;
$$;

drop trigger if exists members_guard_update on public.members;
create trigger members_guard_update
    before update on public.members
    for each row execute function public.guard_member_update();

-- =====================================================================
-- 6) 첫 관리자 지정 (최초 1회)
--    main.html 에서 본인 구글 계정으로 한 번 로그인해서 '승인 대기' 화면이 뜬 뒤,
--    아래 이메일을 본인 것으로 바꿔서 이 줄만 따로 실행하세요.
-- =====================================================================
-- update public.members set status = 'approved', auth_level = 0
--  where email = 'your-email@gmail.com';
