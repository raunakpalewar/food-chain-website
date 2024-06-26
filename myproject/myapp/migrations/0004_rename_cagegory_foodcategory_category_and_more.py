# Generated by Django 4.2.7 on 2023-11-02 10:36

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("myapp", "0003_rename_order_orderdetails_orderitems_and_more"),
    ]

    operations = [
        migrations.RenameField(
            model_name="foodcategory",
            old_name="cagegory",
            new_name="category",
        ),
        migrations.AlterField(
            model_name="fooditem",
            name="food_category",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="foodcategory",
                to="myapp.foodcategory",
            ),
        ),
    ]
