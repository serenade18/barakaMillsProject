from django.db import migrations


def revoke(apps, schema_editor):
    # Hybrid sign-ups used to be given is_staff=True, which let them sign in
    # to Django admin. Only the admin role keeps staff/superuser flags.
    UserAccount = apps.get_model('barakaApp', 'UserAccount')
    UserAccount.objects.exclude(user_type='admin').update(is_staff=False, is_superuser=False)


class Migration(migrations.Migration):

    dependencies = [
        ('barakaApp', '0001_initial'),
    ]

    # Not reversible in a meaningful way (we don't know who had the flags);
    # reversing is a no-op.
    operations = [
        migrations.RunPython(revoke, migrations.RunPython.noop),
    ]
