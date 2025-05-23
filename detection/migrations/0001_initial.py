# Generated by Django 5.2 on 2025-04-16 13:49

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('alert_type', models.CharField(choices=[('SQLI', 'SQL Injection'), ('DDOS', 'DDoS Rate Exceeded')], max_length=5)),
                ('source_ip', models.GenericIPAddressField()),
                ('destination_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('destination_port', models.PositiveIntegerField(blank=True, null=True)),
                ('details', models.TextField(help_text='Details like matched pattern or request count')),
                ('http_payload', models.TextField(blank=True, help_text='Snippet of the triggering payload (if applicable)', null=True)),
            ],
            options={
                'verbose_name': 'Security Alert',
                'verbose_name_plural': 'Security Alerts',
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='DDoSConfig',
            fields=[
                ('config_id', models.PositiveIntegerField(default=1, primary_key=True, serialize=False)),
                ('time_window_seconds', models.PositiveIntegerField(default=60, help_text='Time window in seconds')),
                ('request_threshold', models.PositiveIntegerField(default=100, help_text='Max requests per IP in the window')),
                ('is_active', models.BooleanField(default=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'DDoS Detection Configuration',
                'verbose_name_plural': 'DDoS Detection Configuration',
            },
        ),
        migrations.CreateModel(
            name='SQLiPattern',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pattern', models.CharField(help_text='Regular expression pattern (case-insensitive)', max_length=255, unique=True)),
                ('description', models.CharField(blank=True, max_length=255)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'SQL Injection Pattern',
                'verbose_name_plural': 'SQL Injection Patterns',
            },
        ),
    ]
