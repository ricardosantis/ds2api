import { ShieldAlert } from 'lucide-react'

export default function CompatibilitySection({ t, form, setForm }) {
    return (
        <div className="bg-card border border-border rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-muted-foreground" />
                <h3 className="font-semibold">{t('settings.compatibilityTitle')}</h3>
            </div>
            <p className="text-sm text-muted-foreground">{t('settings.compatibilityDesc')}</p>
            <div className="flex items-center justify-between gap-4">
                <label className="text-sm font-medium">{t('settings.stripReferenceMarkers')}</label>
                <button
                    type="button"
                    role="switch"
                    aria-checked={form.compat?.strip_reference_markers ?? true}
                    onClick={() => setForm((prev) => ({
                        ...prev,
                        compat: { ...prev.compat, strip_reference_markers: !Boolean(prev.compat?.strip_reference_markers ?? true) },
                    }))}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        form.compat?.strip_reference_markers ?? true ? 'bg-primary' : 'bg-muted'
                    }`}
                >
                    <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            form.compat?.strip_reference_markers ?? true ? 'translate-x-6' : 'translate-x-1'
                        }`}
                    />
                </button>
            </div>
        </div>
    )
}
