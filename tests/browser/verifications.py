"""VER-T11-e: the read-only verifications view against the real BFF, cookie session and Postgres (RLS).

The Go harness seeds 30 sessions for organization A (3 pending, 1 completed, 26 expired) and 2 for
organization B, so one page is full (25), a second page exists, and B's rows must never show up.
"""
import re

from playwright.sync_api import expect

from shell_ui import go_to, in_tenant

TENANT_B = '10000000-0000-4000-8000-000000000002'
DIGEST = 'sha256:' + 'ab' * 32


def run_verifications(page, context, config, database, heading, login, artifacts):
    origin = config['origin']
    seeded = database('verification-seed')
    foreign = set(seeded['foreign'])
    assert len(foreign) == 2
    page.goto(origin)
    page.wait_for_load_state('networkidle')
    login(page)
    page.get_by_label('Organización', exact=True).select_option(label='Organización de prueba A')
    page.get_by_role('button', name='Continuar', exact=True).click()
    in_tenant(page, 'Organización de prueba A')

    section = page.get_by_role('region', name='Verificaciones', exact=True)
    rows = section.locator('tbody tr')
    with page.expect_response(lambda r: '/verification-sessions?' in r.url and 'cursor=' not in r.url) as first_feed:
        go_to(page, 'Verificaciones')
    assert first_feed.value.status == 200
    first = first_feed.value.json()
    assert len(first['items']) == 25 and first['nextCursor']
    expect(rows).to_have_count(25)
    expect(section.get_by_role('heading', name='Sesiones de verificación')).to_be_visible()

    # Newest first: the 3 pending ones, then the completed one, then expired sessions.
    assert [item['status'] for item in first['items'][:4]] == ['pending'] * 3 + ['completed']
    completed = first['items'][3]
    assert completed['result'] == 'fail' and completed['codes'] == ['format.header.alg'] and completed['reportDigest'] == DIGEST
    row = rows.nth(3)
    expect(row).to_contain_text('Completada')
    expect(row).to_contain_text('Rechazada')
    expect(row).to_contain_text('format.header.alg')
    expect(row.get_by_text(DIGEST, exact=True)).to_be_attached()
    expect(row.get_by_role('button', name='Copiar la huella completa del reporte')).to_be_visible()
    expect(rows.nth(0)).to_contain_text('Pendiente')
    expect(rows.nth(0)).to_contain_text('—')

    # Real cursor round trip: the second page holds the remaining 5 sessions, none repeated.
    next_button = section.get_by_role('button', name='Siguiente página')
    next_button.focus()
    with page.expect_response(lambda r: '/verification-sessions?' in r.url and 'cursor=' in r.url) as next_feed:
        page.keyboard.press('Enter')
    assert next_feed.value.status == 200
    second = next_feed.value.json()
    expect(section.get_by_role('heading', name='Sesiones de verificación')).to_be_focused()
    expect(rows).to_have_count(5)
    assert second['nextCursor'] is None
    ids = [item['sessionId'] for item in first['items'] + second['items']]
    assert len(ids) == 30 and len(set(ids)) == 30
    assert not foreign & set(ids), "another organization's session was listed"
    expect(next_button).to_have_count(0)
    with page.expect_response(lambda r: '/verification-sessions?' in r.url and 'cursor=' not in r.url):
        section.get_by_role('button', name='Volver al inicio').press('Enter')
    expect(rows).to_have_count(25)

    # Status filter is applied by the server, and the cursor is dropped with it.
    for label, count, badge in [('Pendientes', 3, 'Pendiente'), ('Completadas', 1, 'Completada'), ('Caducadas', 25, 'Caducada')]:
        with page.expect_response(lambda r: '/verification-sessions?' in r.url and 'status=' in r.url) as filtered:
            section.get_by_label('Estado').select_option(label=label)
        assert filtered.value.status == 200
        expect(rows).to_have_count(count)
        expect(section.locator('.badge')).to_have_text([badge] * count)
    section.get_by_label('Estado').select_option(label='Todas')
    expect(rows).to_have_count(25)

    # Rejected requests never reach the store: other tenant, bad filter, bad cursor.
    base = f'{origin}/console/api/tenants/'
    other = context.request.get(f'{base}{TENANT_B}/verification-sessions?limit=25')
    assert other.status in (403, 404), f'foreign tenant read answered {other.status}'
    tenant_a = re.search(r'/tenants/([0-9a-f-]{36})/verification-sessions', first_feed.value.url).group(1)
    assert context.request.get(f'{base}{tenant_a}/verification-sessions?status=bogus').status in (400, 422)
    assert context.request.get(f'{base}{tenant_a}/verification-sessions?cursor=' + 'a' * 40).status in (400, 422)
    assert context.request.post(f'{base}{tenant_a}/verification-sessions', data='{}').status in (404, 405, 403)

    # The page stays inside the viewport at desktop and phone widths (the table scrolls inside its wrapper).
    for width in [1440, 360]:
        page.set_viewport_size({'width': width, 'height': 1000})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(artifacts / f'verifications-{width}.png'), full_page=True)
    page.set_viewport_size({'width': 1440, 'height': 1000})

    # Without verification:read the navigation entry disappears and the BFF answers 403 (no browser-trusted capabilities).
    database('dashboard-readonly')
    denied = context.request.get(f'{base}{tenant_a}/verification-sessions?limit=25')
    assert denied.status == 403, f'read without capability answered {denied.status}'
    page.reload()
    in_tenant(page, 'Organización de prueba A')
    expect(page.get_by_role('navigation', name='Secciones').get_by_role('link', name='Verificaciones', exact=True)).to_have_count(0)

    # Restoring the role brings the view and its data back.
    database('dashboard-admin')
    page.reload()
    in_tenant(page, 'Organización de prueba A')
    with page.expect_response(lambda r: '/verification-sessions?' in r.url) as again:
        go_to(page, 'Verificaciones')
    assert again.value.status == 200
    expect(rows).to_have_count(25)

    # HTTP 401 returns to the provider login with a fresh session and no active organization,
    # which is also the state the next journey starts from.
    page.route('**/verification-sessions?*', lambda route: route.fulfill(status=401, json={'code': 'invalid_credential'}), times=1)
    before = next(c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session')
    section.get_by_role('button', name='Actualizar verificaciones').press('Enter')
    heading(page, 'Elige una organización')
    expect(section).to_have_count(0)
    assert next(c['value'] for c in context.cookies() if c['name'] == 'hukid_test_session') != before
    assert page.evaluate('localStorage.length === 0 && sessionStorage.length === 0')
