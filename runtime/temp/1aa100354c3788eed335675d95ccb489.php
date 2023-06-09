<?php if (!defined('THINK_PATH')) exit(); /*a:4:{s:80:"/www/wwwroot/appstore.nuosike.cn/public/../application/admin/view/kami/edit.html";i:1611375639;s:75:"/www/wwwroot/appstore.nuosike.cn/application/admin/view/layout/default.html";i:1583049508;s:72:"/www/wwwroot/appstore.nuosike.cn/application/admin/view/common/meta.html";i:1583049508;s:74:"/www/wwwroot/appstore.nuosike.cn/application/admin/view/common/script.html";i:1583049508;}*/ ?>
<!DOCTYPE html>
<html lang="<?php echo $config['language']; ?>">
    <head>
        <meta charset="utf-8">
<title><?php echo (isset($title) && ($title !== '')?$title:''); ?></title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<meta name="renderer" content="webkit">

<link rel="shortcut icon" href="/assets/img/favicon.ico" />
<!-- Loading Bootstrap -->
<link href="/assets/css/backend<?php echo \think\Config::get('app_debug')?'':'.min'; ?>.css?v=<?php echo \think\Config::get('site.version'); ?>" rel="stylesheet">

<!-- HTML5 shim, for IE6-8 support of HTML5 elements. All other JS at the end of file. -->
<!--[if lt IE 9]>
  <script src="/assets/js/html5shiv.js"></script>
  <script src="/assets/js/respond.min.js"></script>
<![endif]-->
<script type="text/javascript">
    var require = {
        config:  <?php echo json_encode($config); ?>
    };
</script>
    </head>

    <body class="inside-header inside-aside <?php echo defined('IS_DIALOG') && IS_DIALOG ? 'is-dialog' : ''; ?>">
        <div id="main" role="main">
            <div class="tab-content tab-addtabs">
                <div id="content">
                    <div class="row">
                        <div class="col-xs-12 col-sm-12 col-md-12 col-lg-12">
                            <section class="content-header hide">
                                <h1>
                                    <?php echo __('Dashboard'); ?>
                                    <small><?php echo __('Control panel'); ?></small>
                                </h1>
                            </section>
                            <?php if(!IS_DIALOG && !\think\Config::get('fastadmin.multiplenav')): ?>
                            <!-- RIBBON -->
                            <div id="ribbon">
                                <ol class="breadcrumb pull-left">
                                    <li><a href="dashboard" class="addtabsit"><i class="fa fa-dashboard"></i> <?php echo __('Dashboard'); ?></a></li>
                                </ol>
                                <ol class="breadcrumb pull-right">
                                    <?php foreach($breadcrumb as $vo): ?>
                                    <li><a href="javascript:;" data-url="<?php echo $vo['url']; ?>"><?php echo $vo['title']; ?></a></li>
                                    <?php endforeach; ?>
                                </ol>
                            </div>
                            <!-- END RIBBON -->
                            <?php endif; ?>
                            <div class="content">
                                <form id="edit-form" class="form-horizontal" role="form" data-toggle="validator" method="POST" action="">

    <div class="form-group">
        <label class="control-label col-xs-12 col-sm-2"><?php echo __('Kami'); ?>:</label>
        <div class="col-xs-12 col-sm-8">
            <input id="c-kami" data-rule="required" class="form-control" name="row[kami]" type="text" value="<?php echo htmlentities($row['kami']); ?>">
        </div>
    </div>
    <div class="form-group">
        <label class="control-label col-xs-12 col-sm-2"><?php echo __('Udid'); ?>:</label>
        <div class="col-xs-12 col-sm-8">
            <input id="c-udid" data-rule="required" class="form-control" name="row[udid]" type="text" value="<?php echo htmlentities($row['udid']); ?>">
        </div>
    </div>

	<div class="form-group">
        <label class="control-label col-xs-12 col-sm-2"><?php echo __('Kmyp'); ?>:</label>
        <div class="col-xs-12 col-sm-8">
            <?php echo build_radios('row[kmyp]', ['1'=>'月卡', '2'=>'季卡', '3'=>'年卡'], $row['kmyp']); ?>
        </div>
    </div>
	<div class="form-group">
        <label class="control-label col-xs-12 col-sm-2"><?php echo __('Jh'); ?>:</label>
        <div class="col-xs-12 col-sm-8">
            <?php echo build_radios('row[jh]', ['0'=>'未激活', '1'=>'已激活'], $row['jh']); ?>
        </div>
    </div>

    
    <div class="form-group">
        <label class="control-label col-xs-12 col-sm-2"><?php echo __('Addtime'); ?>:</label>
        <div class="col-xs-12 col-sm-8">
            <input id="c-addtime" data-rule="required" class="form-control datetimepicker" data-date-format="YYYY-MM-DD HH:mm:ss" data-use-current="true" name="row[addtime]" type="text" value="<?php echo $row['addtime']?datetime($row['addtime']):''; ?>">
        </div>
    </div>
    <div class="form-group">
        <label class="control-label col-xs-12 col-sm-2"><?php echo __('Usetime'); ?>:</label>
        <div class="col-xs-12 col-sm-8">
            <input id="c-usetime" data-rule="required" class="form-control datetimepicker" data-date-format="YYYY-MM-DD HH:mm:ss" data-use-current="true" name="row[usetime]" type="text" value="<?php echo $row['usetime']?datetime($row['usetime']):''; ?>">
        </div>
    </div>
    <div class="form-group">
        <label class="control-label col-xs-12 col-sm-2"><?php echo __('Endtime'); ?>:</label>
        <div class="col-xs-12 col-sm-8">
            <input id="c-endtime" data-rule="required" class="form-control datetimepicker" data-date-format="YYYY-MM-DD HH:mm:ss" data-use-current="true" name="row[endtime]" type="text" value="<?php echo $row['endtime']?datetime($row['endtime']):''; ?>">
        </div>
    </div>
    
    <div class="form-group layer-footer">
        <label class="control-label col-xs-12 col-sm-2"></label>
        <div class="col-xs-12 col-sm-8">
            <button type="submit" class="btn btn-success btn-embossed disabled"><?php echo __('OK'); ?></button>
            <button type="reset" class="btn btn-default btn-embossed"><?php echo __('Reset'); ?></button>
        </div>
    </div>
</form>

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script src="/assets/js/require<?php echo \think\Config::get('app_debug')?'':'.min'; ?>.js" data-main="/assets/js/require-backend<?php echo \think\Config::get('app_debug')?'':'.min'; ?>.js?v=<?php echo htmlentities($site['version']); ?>"></script>
    </body>
</html>