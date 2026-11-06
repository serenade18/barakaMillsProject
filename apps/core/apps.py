from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Owns the shared `barakaApp` label and its migrations.

    The domain apps under apps/ define their models with
    `Meta.app_label = "barakaApp"`, so all models still live in one
    migration history and map to the original tables.
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'
    label = 'barakaApp'
