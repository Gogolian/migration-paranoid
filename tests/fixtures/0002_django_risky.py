from django.db import migrations


class Migration(migrations.Migration):
    dependencies = []
    operations = [
        migrations.RemoveField(model_name="user", name="legacy"),
        migrations.RenameField(model_name="user", old_name="name", new_name="full_name"),
        migrations.DeleteModel(name="OldThing"),
    ]
