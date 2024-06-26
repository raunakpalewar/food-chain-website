# Generated by Django 4.2.7 on 2023-11-04 12:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("myapp", "0008_orderitems_location_alter_userregistration_role"),
    ]

    operations = [
        migrations.AddField(
            model_name="orderitems",
            name="restaurant",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="order_history",
                to="myapp.restaurant",
            ),
        ),
    ]
