# Generated by Django 4.2.7 on 2023-11-02 09:17

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("myapp", "0002_restaurant_owner_userregistration_address_and_more"),
    ]

    operations = [
        migrations.RenameModel(
            old_name="Order",
            new_name="OrderDetails",
        ),
        migrations.CreateModel(
            name="OrderItems",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("quantity", models.PositiveIntegerField(default=1)),
                ("amount", models.DecimalField(decimal_places=2, max_digits=10)),
                (
                    "item_name",
                    models.ManyToManyField(related_name="orders", to="myapp.fooditem"),
                ),
            ],
        ),
        migrations.AlterField(
            model_name="orderdetails",
            name="items",
            field=models.ManyToManyField(related_name="orders", to="myapp.orderitems"),
        ),
    ]
