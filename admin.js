async function api(path, opts = {}) {
    const res = await fetch(path, Object.assign({credentials:'include', headers:{'Content-Type':'application/json'}}, opts));
    return res.json();
}

async function refreshGodMode() {
    const r = await api('/admin/settings');
    document.getElementById('godStatus').innerText = r.settings.godModeEnabled ? 'ENABLED' : 'OFF';
}

window.addEventListener('load', () => {
    refreshGodMode();
    document.getElementById('enableGod').addEventListener('click', async () => {
        const key = document.getElementById('masterKey').value;
        await api('/admin/godmode/toggle', { method:'POST', body: JSON.stringify({action:'enable', masterKey:key}) });
        refreshGodMode();
    });
    document.getElementById('disableGod').addEventListener('click', async () => {
        const key = document.getElementById('masterKey').value;
        await api('/admin/godmode/toggle', { method:'POST', body: JSON.stringify({action:'disable', masterKey:key}) });
        refreshGodMode();
    });
});
