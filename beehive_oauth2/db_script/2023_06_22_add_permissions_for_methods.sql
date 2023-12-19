-- get id for ApiMethod type
set @tipo =( select id from sysobject_type st where objtype = 'service' and objdef = 'ApiMethod' );

-- show ApiMethod type
select @tipo;

-- get id for permission for all methods (*) all action (*)
set @perm = ( select sp.id
        from
            sysobject_permission sp
            inner join sysobject s on sp.obj_id = s.id
            inner join sysobject_type st on s.type_id = st.id
            inner join sysobject_action sa on sp.action_id = sa.id
        where
            s.objid = '*'
            and sa.value = '*'
            and s.type_id = cast(@tipo as integer)
    );
-- show permission
SELECT @perm;

-- add permessions for all methods to known roles
-- this insert is idempotent
insert into role_permission (role_id, permission_id)
select id, @perm
from
    `role` r
where
    ( name like 'Api%' or name like 'DivViewerRole%' or name like 'DivAdminRole%' or name like 'AccountViewerRole%'
     or name like 'AccountAdminRole%' or name like 'OrgViewerRole%' or name like 'OrgOperatorRole%'
    )
    AND r.ID NOT IN ( SELECT rp.role_id FROM role_permission rp WHERE rp.permission_id = cast(@perm as integer) );


-- this insert is idempotent
-- add permessions for all methods to known groups
insert into role_permission (role_id, permission_id)
select r.id, @perm
from
    `role` r
    inner join roles_groups rg on rg.role_id = r.id
    inner JOIN `group` g on g.id = rg.group_id
where
    g.name in (
        'Administrator', 'Pilot', 'Portali', 'NivolaPortal', 'Ada',
        'Fornitori', 'Maggioli', 'UserCsi', 'DbaCsi', 'Maggioli-Garetel',
        'Tester', 'gr-clitest', 'gies-RPTurismo'
    )
    AND r.id NOT IN ( SELECT rp.role_id FROM role_permission rp WHERE rp.permission_id = cast(@perm as integer) );
