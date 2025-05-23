# Generated by Django 5.1.7 on 2025-04-09 10:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('payments', '0005_delete_customertransaction'),
    ]

    operations = [
        migrations.CreateModel(
            name='SecurityProtocol',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('version', models.CharField(max_length=50)),
                ('description', models.TextField()),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'security_protocol',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='UserAccountStatus',
            fields=[
                ('email', models.EmailField(max_length=254, primary_key=True, serialize=False)),
                ('password', models.CharField(max_length=255)),
                ('first_name', models.CharField(max_length=50)),
                ('last_name', models.CharField(max_length=50)),
                ('phone_number', models.CharField(blank=True, max_length=20, null=True)),
                ('address', models.CharField(blank=True, max_length=255, null=True)),
                ('city', models.CharField(blank=True, max_length=50, null=True)),
                ('state', models.CharField(blank=True, max_length=50, null=True)),
                ('country', models.CharField(blank=True, max_length=50, null=True)),
                ('zip_code', models.CharField(blank=True, max_length=20, null=True)),
                ('role_id', models.IntegerField()),
                ('account_status', models.CharField(default='Available', max_length=20)),
            ],
            options={
                'db_table': 'user_account_status',
                'managed': False,
            },
        ),
        migrations.CreateModel(
            name='TokenVault',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(max_length=36, unique=True)),
                ('encrypted_card_number', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'payments_tokenvault',
            },
        ),
        migrations.AddField(
            model_name='merchanttransaction',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('success', 'Success'), ('failed', 'Failed')], default='pending', max_length=10),
        ),
    ]
