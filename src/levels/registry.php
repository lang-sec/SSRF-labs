<?php

declare(strict_types=1);

require_once __DIR__ . '/../support/DnsResolver.php';
require_once __DIR__ . '/../support/MissingInputException.php';
require_once __DIR__ . '/../support/HttpResponse.php';
require_once __DIR__ . '/../support/NetworkGuard.php';
require_once __DIR__ . '/../support/HttpClient.php';
require_once __DIR__ . '/../support/BusinessController.php';
require_once __DIR__ . '/TargetProbeController.php';
require_once __DIR__ . '/LogoImportController.php';
require_once __DIR__ . '/CampaignAssetController.php';
require_once __DIR__ . '/LinkPreviewController.php';
require_once __DIR__ . '/AvatarPreviewController.php';
require_once __DIR__ . '/AttachmentPreviewController.php';
require_once __DIR__ . '/SocialAvatarController.php';
require_once __DIR__ . '/AssetMigrationController.php';
require_once __DIR__ . '/PartnerMediaController.php';
require_once __DIR__ . '/RichPreviewController.php';
require_once __DIR__ . '/WebhookTestController.php';
require_once __DIR__ . '/ReportExportController.php';
require_once __DIR__ . '/CreativeCollectorController.php';
require_once __DIR__ . '/CloudAssetController.php';
require_once __DIR__ . '/ShareCardController.php';
require_once __DIR__ . '/RssImportController.php';

/**
 * 每关一个控制器文件：class/action/source 都在这里登记。
 */
function lab_level_handlers(): array
{
    return [
        1 => [
            'class' => \SsrfLab\Levels\TargetProbeController::class,
            'action' => 'probe',
            'source' => __DIR__ . '/TargetProbeController.php',
        ],
        2 => [
            'class' => \SsrfLab\Levels\LogoImportController::class,
            'action' => 'import',
            'source' => __DIR__ . '/LogoImportController.php',
        ],
        3 => [
            'class' => \SsrfLab\Levels\CampaignAssetController::class,
            'action' => 'check',
            'source' => __DIR__ . '/CampaignAssetController.php',
        ],
        4 => [
            'class' => \SsrfLab\Levels\LinkPreviewController::class,
            'action' => 'preview',
            'source' => __DIR__ . '/LinkPreviewController.php',
        ],
        5 => [
            'class' => \SsrfLab\Levels\AvatarPreviewController::class,
            'action' => 'preview',
            'source' => __DIR__ . '/AvatarPreviewController.php',
        ],
        6 => [
            'class' => \SsrfLab\Levels\AttachmentPreviewController::class,
            'action' => 'preview',
            'source' => __DIR__ . '/AttachmentPreviewController.php',
        ],
        7 => [
            'class' => \SsrfLab\Levels\SocialAvatarController::class,
            'action' => 'sync',
            'source' => __DIR__ . '/SocialAvatarController.php',
        ],
        8 => [
            'class' => \SsrfLab\Levels\AssetMigrationController::class,
            'action' => 'migrate',
            'source' => __DIR__ . '/AssetMigrationController.php',
        ],
        9 => [
            'class' => \SsrfLab\Levels\PartnerMediaController::class,
            'action' => 'sync',
            'source' => __DIR__ . '/PartnerMediaController.php',
        ],
        10 => [
            'class' => \SsrfLab\Levels\RichPreviewController::class,
            'action' => 'preview',
            'source' => __DIR__ . '/RichPreviewController.php',
        ],
        11 => [
            'class' => \SsrfLab\Levels\WebhookTestController::class,
            'action' => 'test',
            'source' => __DIR__ . '/WebhookTestController.php',
        ],
        12 => [
            'class' => \SsrfLab\Levels\ReportExportController::class,
            'action' => 'export',
            'source' => __DIR__ . '/ReportExportController.php',
        ],
        13 => [
            'class' => \SsrfLab\Levels\CreativeCollectorController::class,
            'action' => 'collect',
            'source' => __DIR__ . '/CreativeCollectorController.php',
        ],
        14 => [
            'class' => \SsrfLab\Levels\CloudAssetController::class,
            'action' => 'import',
            'source' => __DIR__ . '/CloudAssetController.php',
        ],
        15 => [
            'class' => \SsrfLab\Levels\ShareCardController::class,
            'action' => 'create',
            'source' => __DIR__ . '/ShareCardController.php',
        ],
        16 => [
            'class' => \SsrfLab\Levels\RssImportController::class,
            'action' => 'import',
            'source' => __DIR__ . '/RssImportController.php',
        ],
    ];
}
