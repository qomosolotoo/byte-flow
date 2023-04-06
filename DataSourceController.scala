package controllers

import com.guandata.core.base.utils.RandUtil
import com.guandata.core.base.{
  FieldData,
  FilterComposeNode,
  FilterNode,
  FilterValueNode,
  ManipulateDFQuery,
  PageQueryRequest,
  QueryType,
  SecurityFilterContext,
  TableQueryDefinition
}
import com.mohiva.play.silhouette.api.Silhouette
import controllers.base.auth_checker.AuthFromResourceOwnerController
import controllers.responses.ErrorResponse.{FETCH_DATA_ERROR, INVALID_DATA_SOURCE, INVALID_PARAMETERS}
import controllers.responses._
import domain.audit_log.definition.AuditOpTypes
import domain.audit_log.util.base.AuditHelper
import domain.auth.service.ResourcePermissionManagementService
import domain.resource_access.app.{ResourceAccChecker, ResourceAccFetcher, ResourceAccUpdater}
import domain.resource_io.utils.IOFileHelpers
import domain.resource_io.utils.IOFileHelpers.{ContentTypeDefinition, DownloadFileRequest}
import domain.smart_etl.service.SmartETLQueryService
import domain.table2d_io.model.Table2dFile
import domain.table2d_io.model.Table2dFile.DefaultTable2dFile
import expceptions.{AbstractBusinessException, NotFoundException, PermissionDeniedException}
import guandata_zipkin.{TraceData, ZipkinTraceServiceLike}
import job_manager.JobManager
import job_manager.task.{PreviewAdlsGen2Task, SimpleTask, TaskParam}
import models.DataSourceOriginSourceType.DataSourceOriginSourceType
import models.DsConfigKeys._
import models.TagRecordType.DATA_SET
import models.{
  AdlsGen2FileQuery,
  ChangeAccountAPI,
  ChangeQueryAPI,
  ChartCard,
  CompareFieldAPI,
  CreateDsFromAccountQuery,
  CreateDsFromAdlsGen2Query,
  CreateDsFromAdlsQuery,
  CreateDsFromFtpQuery,
  CronDefinition,
  DataSettingForETLDataSet,
  DataSettingQuery,
  DataSettingQueryForZhaoHang,
  DataSourceAPI,
  DataSourceDataQuery,
  DataSourceFilterQuery,
  DataSourceInfo,
  DataSourceOriginSourceType,
  DataSourceRowFilter,
  DataSourceRule,
  DataSourcesSettings,
  DataTriggerRefreshQuery,
  DesensitizationPermissionEffectiveRange,
  DirType,
  DisplayType,
  DsFieldInfo,
  DsFilter,
  FieldAPI,
  FieldAssocAPI,
  FieldMap,
  GuanIndexIncrementalUpdateSetting,
  GuandataConfiguration,
  HotReloadConfiguration,
  PermissionType,
  QueryParamOfCreateDsAPI,
  RenameDatasetAPI,
  SecurityFilterRules,
  SecurityFilterSwitchConfigName,
  SecurityFilterTemplateRepository,
  TableQueryPreviewQuery,
  TagRecordType,
  TaskStatus,
  TaskType,
  UniverseDsRefresh,
  UpdateColNameTypeReq,
  UserAPI
}
import org.apache.commons.lang3.StringUtils
import play.api.libs.Files
import play.api.libs.json._
import play.api.mvc.{Action, AnyContent, MultipartFormData, Result}
import services.dataset_update.guan_index.GuanIndexUpdateManager
import services.datasource.domain_object.request.BatchChangeDirectoryRequest
import services.datasource.model.DatasourceUpdateException
import services.datasource.{
  DatasourceTemplateService,
  DatasourceUpdateProperties,
  DatasourceUpdateSetting,
  DatasourceUpdateTrigger
}
import services.dynamic_parameter.DynamicParameterAdapter
import services.dynamic_parameter.model.AttachDpInfo
import services.dynamic_parameter.service.param_parser.ParamParserInstances._
import services.dynamic_parameter.service.value_binder.ValueBinderInstances._
import services.security_filter_template.SecurityFilterTemplateService
import services.task.JobHelper.taskId2Response
import services.{DataSourceService, _}
import utils.auth.{JWTEnv, SecureController}
import utils.permission._
import utils.{Base64Util, BuiltInSql, Constants, FutureUtil}

import java.io.File
import java.nio.charset.StandardCharsets
import java.sql.Timestamp
import java.text.SimpleDateFormat
import javax.inject.{Inject, Provider, Singleton}
import scala.concurrent.Future.successful
import scala.concurrent.{ExecutionContext, Future}

/**
 * Created by Bytes on 8/18/16.
 */
@Singleton
class DataSourceController @Inject() (
    val silhouette: Silhouette[JWTEnv],
    val tracer: ZipkinTraceServiceLike,
    private val dataSources: DataSourceService,
    private val dataSecurityManager: DataSecurityManager,
    private val storageManager: StorageManager,
    private val schemaManager: SchemaManager,
    private val dataSourceUpdateProperties: DatasourceUpdateProperties,
    private val datasourceMetaInfoManager: DatasourceMetaInfoManager,
    private val datasourceUpdateTrigger: DatasourceUpdateTrigger,
    private val guanIndexUpdateManager: GuanIndexUpdateManager,
    private val accounts: AccountService,
    private val cards: CardService,
    private val fields: Fields,
    private val users: Users,
    private val computationService: ComputationService,
    private val dataSourceUpdate: DataSourceUpdate,
    private val config: HotReloadConfiguration,
    private val directories: DirectoryService,
    private val dataSourcesSettings: DataSourcesSettings,
    private val datasourceUpdateSetting: DatasourceUpdateSetting,
    private val smartETLQueryService: SmartETLQueryService,
    private val cardManipulate: CardManipulate,
    private val securityFilterTemplate: SecurityFilterTemplateRepository,
    private val jobManager: JobManager,
    private val pages: PageService,
    private val dpAdapter: DynamicParameterAdapter,
    private val rtDsService: RealtimeDataSourceService,
    private val resourceUpdateHistoryService: ResourceUpdateHistoryService,
    private val cardToDataSourceService: CardToDataSourceService,
    private val sparkViewService: SparkViewService,
    private val universeTableService: UniverseTableService,
    private val datasourceTemplateService: DatasourceTemplateService,
    private val desensitizationRuleService: DesensitizationRuleService,
    private val desensitizationPermissionService: DesensitizationPermissionService,
    val accountRolePrivilege: AccountRolePrivilege,
    val resourcePermissionManagementService: Provider[ResourcePermissionManagementService],
    private val resourceAccChecker: ResourceAccChecker,
    private val resourceAccUpdater: ResourceAccUpdater,
    private val resourceAccFetcher: ResourceAccFetcher,
    private val securityFilterTemplateService: SecurityFilterTemplateService,
    val controllerComponents: play.api.mvc.ControllerComponents,
    val azureService: AzureService
)(implicit val ec: ExecutionContext)
    extends SecureController
    with AuthFromResourceOwnerController
    with AuditHelper {

  def preview(dsId: String, sortField: Option[String], order: Option[String]): Action[JsValue] =
    SecuredPostActionAsync[DataSourceFilterQuery](DatasetResource, ReadPrivilege) {
      implicit request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domId.get
        val previewQuery: DataSourceFilterQuery = request.body
        val filterQuery = previewQuery.filter
        val sorting: Option[SortFactor] = previewQuery.sortFactor
        // 准备将filterQuery转化为securityFilter

        (for {
          readable <- resourceAccChecker.canUseNonDirResource(user, dsId, TagRecordType.DATA_SET)
          res <-
            if (readable) {
              datasourceMetaInfoManager.getWithCols(domId, dsId).flatMap {
                case Some(dsAPI) =>
                  val dsFieldInfo = DsFieldInfo.buildDsFieldInfo(dsAPI.columns.get, dsAPI)
                  val dynamicParameters =
                    dsAPI.config.flatMap(config => (config \ "dynamicParameters").asOpt[Seq[AttachDpInfo]])
                  val desensitizationTemplateId = dsAPI.config
                    .flatMap(config => (config \ DATA_DESENSITIZATION).asOpt[JsObject])
                    .flatMap(dataDesensitization => (dataDesensitization \ DESENSITIZATION_TEMPLATE_ID).asOpt[String])
                  (for {
                    nfilterQuery <-
                      dpAdapter
                        .resolve(
                          domId,
                          Json.toJson(filterQuery).toString,
                          Json.toJson(filterQuery).toString,
                          dynamicParameters
                        )
                        .map(Json.parse(_).asOpt[DataSourceRowFilter])

                    previewFilter: Option[FilterNode] = nfilterQuery.flatMap(dataSources.transferDsRowFilter)
                    ndsAPI <- dpAdapter.resolve(domId, dsAPI, dsAPI, dynamicParameters)
                    userInfo <- users.get(domId, user.uId.get)
                    securityFilterMap <-
                      securityFilterTemplateService.getSecurityFilterMap(userInfo.getOrElse(user), ndsAPI)
                    nDsFieldInfo <- dpAdapter.resolve(domId, dsFieldInfo, dsFieldInfo, dynamicParameters)
                    invisibleColumns = securityFilterMap
                      .get(dsId)
                      .flatMap(_.columnLevelFilter.map(_.filter(!_.visible).map(_.name)))
                      .getOrElse(Seq.empty)
                    nPreviewFilter: Option[FilterNode] = previewFilter
                      .map(getRealFilterFormula(_, nDsFieldInfo.columns))
                    prevData <- dataSources.preview(
                      domId,
                      nDsFieldInfo,
                      securityFilterMap,
                      nPreviewFilter,
                      previewQuery.limit.getOrElse(30),
                      previewQuery.offset.getOrElse(0),
                      None,
                      sorting,
                      operator = Some(user)
                    )
                    // 如果该数据集上有行列权限或者筛选条件，则重新计算可以预览的rowCount
                    rowCountOpt <-
                      if (
                        !dsAPI.displayType.equals(DisplayType.SPARK_VIEW) &&
                        (securityFilterMap.nonEmpty || nPreviewFilter.nonEmpty)
                      )
                        computationService.getDsRowCount(
                          domId,
                          nDsFieldInfo,
                          dataSources,
                          securityFilterMap = securityFilterMap,
                          previewFilter = previewFilter
                        )
                      else Future.successful(Right(None))
                    needDesensitization <- desensitizationPermissionService
                      .needDesensitization(
                        domId,
                        user.uId.get,
                        dsId,
                        DesensitizationPermissionEffectiveRange.ALL,
                        user.loginId
                      )
                    desensitizationRuleList <-
                      if (needDesensitization) {
                        desensitizationRuleService.getRuleList(domId, dsAPI.columns.get, desensitizationTemplateId)
                      } else Future.successful(Seq.empty)
                  } yield {
                    val desensitizationData =
                      if (needDesensitization)
                        dataSources.previewDataWithDesensitize(prevData, desensitizationRuleList)
                      else prevData
                    val allColumnsLength = dsAPI.columns.map(_.length)
                    val colCount = previewQuery.cols.map(_.size).orElse(allColumnsLength)
                    val columns = dsAPI.columns.map(
                      _.map(column => column.copy(isRestricted = Some(invisibleColumns.contains(column.name.get))))
                    )
                    val nDsAPI = rowCountOpt match {
                      case Right(rowCount) if rowCount.isDefined =>
                        dsAPI.copy(rowCount = Some(rowCount.get), colCount = colCount, columns = columns)
                      case _ =>
                        dsAPI.copy(colCount = colCount, columns = columns)
                    }
                    val res = Json.toJson(nDsAPI).as[JsObject] ++ Json.obj("preview" -> desensitizationData)
                    SuccessResponse(res)
                  }).recover {
                    case _: Exception
                        if dsAPI.status.contains(TaskStatus.UPDATING) || dsAPI.status.contains(TaskStatus.CREATING) =>
                      notFound(traceData.getI18NMessage("NOT_FOUND.previewWhenUpdating"))
                  }
                case _ =>
                  errFuture(ErrorResponse.NOT_FOUND, traceData.getI18NMessage("NOT_FOUND.dataSourceNotFound"))(
                    NotifyType.VALIDATE
                  )
              }
            } else
              Future.successful(errorResponse(PermissionDeniedException()))
        } yield res).recover { case ex: java.util.NoSuchElementException =>
          notFound(traceData.getI18NMessage("NOT_FOUND.datasetNotFound"))
          logger.error(ex.getStackTrace.mkString("\n"))
          ErrorResponse(ErrorResponse.NOT_FOUND, traceData.getI18NMessage("NOT_FOUND.datasetNotFound"))
        }
    }

  // T7773 前端preview-with-filter时给后端的filter.conditions是字段未改变前的定义，这里通过columns的来更换为最新的foluma
  private def getRealFilterFormula(previewFilter: FilterNode, columns: Seq[FieldAPI]): FilterNode = {
    val fdIdFormulaMap = columns.map { column => column.fdId -> column.formula }.toMap
    val filterValueNode = previewFilter.asInstanceOf[FilterComposeNode]
    val filterValueComponents = filterValueNode.components.zipWithIndex.map { case (component, idx) =>
      val fieldData: FieldData = component.asInstanceOf[FilterValueNode].value
      val filterNodeValue = fieldData.copy(formula = fdIdFormulaMap.getOrElse(fieldData.fdId, fieldData.formula))
      FilterValueNode(
        value = filterNodeValue,
        placeholder = Some(ManipulateDFQuery.filterPlaceholderPatten + (idx + 1))
      )
    }
    filterValueNode.copy(components = filterValueComponents)
  }

  /**
   * 搜索数据集列表
   */
  def search(name: Option[String], dsId: Option[String], limit: Int, offset: Int): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = request.identity.get.domId.get
      datasourceMetaInfoManager.searchDsByName(user, name, domId, limit, offset).flatMap {
        case dsSeq if dsSeq.nonEmpty =>
          val res = dsSeq.map { ds => Json.toJson(ds).as[JsObject] }
          Future.successful(SuccessResponse(res))
        case _ =>
          Future.successful(
            ErrorResponse(
              ErrorResponse.NOT_FOUND,
              traceData.getI18NMessage("NOT_FOUND.dataSourceNotFound"),
              NotifyType.VALIDATE
            )
          )
      }
    }

  def rename(): Action[JsValue] = SecuredPostActionAsync[RenameDatasetAPI](DatasetResource, UpdatePrivilege) {
    request => implicit traceData: TraceData =>
      val renameDataSource = request.body

      val dsId = renameDataSource.dsId
      val user = request.identity.get
      val domId = user.domId.get
      (for {
        isOwner <- resourceAccChecker.canUseNonDirResource(user, dsId, TagRecordType.DATA_SET)
        res <-
          if (isOwner) {
            datasourceMetaInfoManager.getNameAndParentDirIdByDsId(domId, renameDataSource.dsId).flatMap {
              case Some((_, parentDirId)) =>
                dataSourceUpdateProperties
                  .checkDirOfDsToErrMsg(domId, Some(dsId), Some(parentDirId), renameDataSource.name)
                  .flatMap {
                    case Left((errCode, errMsg)) =>
                      Future.successful(ErrorResponse(errCode, errMsg))
                    case Right(_) =>
                      val renameFuture = datasourceMetaInfoManager.rename(domId, renameDataSource, parentDirId, cards)
                      datasourceMetaInfoManager.get(domId, dsId).flatMap { dsOpt =>
                        callUniverRenameUrl(dsOpt, renameDataSource.name, domId)
                          .flatMap(_ => renameFuture.map(_ => SuccessResponse("DataSource renamed")))
                      }
                  }
              case _ =>
                errorResFuture(NotFoundException(traceData.getI18NMessage("NOT_FOUND.directoryNotFound")))
            }
          } else
            errorResFuture(PermissionDeniedException())
      } yield res).recover { case ex: java.util.NoSuchElementException =>
        logger.error(ex.getStackTrace.mkString("\n"))
        errorResponse(NotFoundException(traceData.getI18NMessage("NOT_FOUND.datasetNotFound")))
      }
  }

  private def callUniverRenameUrl(dsOpt: Option[DataSourceAPI], dsNewName: String, domId: String)(implicit
      traceData: TraceData
  ) = {
    val cnId = dsOpt.flatMap(_.cnId)
    if (cnId.contains("universe")) {
      val tableId = dsOpt.flatMap(ds => ds.config.map(x => (x \ "tableQuery" \ "query").as[String]))
      val dsId = dsOpt.flatMap(_.dsId)
      universeTableService.renameDataSourceCallback(tableId.get, dsId.get, dsNewName, domId)
    } else
      Future.successful(None)
  }

  def getDataWithFilter(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSourceDataQuery](DatasetResource, ReadPrivilege) {
      implicit request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domId.get
        val query = request.body
        val includeDerivedColumn = query.includeDerivedColumn.getOrElse(false)
        resourceAccChecker
          .canExportResource(user, dsId, TagRecordType.DATA_SET)
          .flatMap {
            case true =>
              val dsApiFuture =
                if (includeDerivedColumn)
                  datasourceMetaInfoManager.getWithCols(domId, dsId)
                else datasourceMetaInfoManager.getWithPhysicalCols(domId, dsId)

              dsApiFuture.flatMap {
                case Some(dsAPI) =>
                  val dsFieldInfo = DsFieldInfo.buildDsFieldInfo(dsAPI.columns.get, dsAPI)
                  for {
                    securityFilterMap <- securityFilterTemplateService.getSecurityFilterMap(user, dsAPI)

                    limit <- domainService.getSettings(domId).map {
                      _.exportLimit
                        .flatMap { exportLimitJs =>
                          (exportLimitJs \ "maxDatasetExportRowCount").asOpt[Int]
                        }
                        .getOrElse(10000)
                    }

                    prevData <- dataSources.preview(
                      domId,
                      dsFieldInfo,
                      securityFilterMap,
                      None,
                      limit,
                      0,
                      query.filters,
                      operator = Some(user)
                    )
                  } yield {
                    val res = Json.toJson(dsAPI).as[JsObject] ++
                      Json.obj("preview" -> prevData, "colCount" -> dsAPI.columns.get.size)
                    SuccessResponse(res)
                  }

                case _ => errorResFuture(NotFoundException("NOT_FOUND.dataSourceNotFound"))
              }
            case false => errorResFuture(PermissionDeniedException())
          }
    }

  def getDataCountWithFilter(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSourceDataQuery](DatasetResource, ReadPrivilege) {
      implicit request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domId.get
        val query = request.body
        val includeDerivedColumn = query.includeDerivedColumn.getOrElse(false)
        (for {
          readable <- resourceAccChecker.canUseNonDirResource(user, dsId, TagRecordType.DATA_SET)
          res <-
            if (readable) {
              val dsApiFuture =
                if (includeDerivedColumn)
                  datasourceMetaInfoManager.getWithCols(domId, dsId, needReplacedDynamic = true)
                else datasourceMetaInfoManager.getWithPhysicalCols(domId, dsId)
              dsApiFuture.flatMap {
                case Some(dsAPI) =>
                  val dsFieldInfo = DsFieldInfo.buildDsFieldInfo(dsAPI.columns.get, dsAPI)
                  for {
                    securityFilterMap <- securityFilterTemplateService.getSecurityFilterMap(user, dsAPI)
                    rowCount <- dataSources.getCountWithFilter(domId, dsFieldInfo, securityFilterMap, query.filters)
                  } yield {
                    val res =
                      Json.obj("rowCount" -> rowCount.fold(0L)(identity), "colCount" -> dsFieldInfo.columns.size)
                    SuccessResponse(res)
                  }
                case _ => errorResFuture(NotFoundException("NOT_FOUND.dataSourceNotFound"))
              }
            } else {
              errorResFuture(PermissionDeniedException())
            }
        } yield res).recover { case _: java.util.NoSuchElementException =>
          ErrorResponse(ErrorResponse.NOT_FOUND, traceData.getI18NMessage("NOT_FOUND.datasetNotFound"))
        }
    }

  private def getSourceCardInfo(domId: String, acId: Option[String], user: UserAPI)(implicit
      traceData: TraceData
  ) = {
    if (acId.isDefined) {
      val cdId = acId.get
      for {
        actualPgId <- cards.getCardPageId(domId, cdId)
        routePgId = if (actualPgId.isDefined && actualPgId.get.nonEmpty) actualPgId else None
        cardOpt <- cards.get(cdId, user, routePgId)
      } yield {
        val jsObject = cardOpt
          .map { card =>
            val chartCard = card.asInstanceOf[ChartCard]
            val dsInfo = chartCard.content
              .flatMap(_.dsInfo)
              .map(_.copy(acId = None, aliasMap = None, columns = Seq.empty, config = None))
            val cardJson = Json.toJsObject(chartCard.copy(content = chartCard.content.map(_.copy(dsInfo = dsInfo))))
            Json.obj("cardMeta" -> cardJson, "cardId" -> cdId, "cardName" -> chartCard.name)
          }
          .getOrElse(Json.obj("cardId" -> cdId))
        Some(jsObject)
      }
    } else {
      Future.successful(None)
    }
  }

  private def getModelInfo(user: UserAPI, dsAPI: DataSourceAPI, editable: Option[Boolean] = None)(implicit
      traceData: TraceData
  ): Future[Option[JsObject]] = {
    val domId = user.domId.get
    val r = dsAPI.displayType match {
      case DisplayType.CARD =>
        getSourceCardInfo(domId, dsAPI.acId, user: UserAPI).map(x => Some(Json.obj("model" -> x)))
      case DisplayType.DATAFLOW =>
        datasourceMetaInfoManager
          .getETLModel(domId, dsAPI.dsId.get)
          .map(x => Some(Json.obj("model" -> x)))
      case DisplayType.DATAFUSION =>
        datasourceMetaInfoManager
          .getFusionModel(domId, dsAPI.dsId.get)
          .map(x => Some(Json.obj("model" -> x)))
      case DisplayType.REAL_TIME =>
        rtDsService
          .getModel(dsAPI, editable = editable.getOrElse(false))
          .map(x => Some(Json.obj("model" -> x)))
      case DisplayType.FEEDBACK =>
        cardToDataSourceService
          .getFeedbackDsModel(user, dsAPI.dsId.get, pages)
          .map(x => Some(Json.obj("model" -> x)))
      case DisplayType.CARD_RESULT =>
        cardToDataSourceService
          .getCardResultDsModel(user, dsAPI.dsId.get, pages)
          .map(x => Some(Json.obj("model" -> x)))
      case DisplayType.SPARK_VIEW =>
        datasourceMetaInfoManager
          .getSparkViewModel(dsAPI, user)
          .map(x => Some(Json.obj("model" -> x)))
      case DisplayType.UNIVERSE =>
        datasourceMetaInfoManager.getUniverseModel(domId, dsAPI.dsId.get, user)
      case DisplayType.WEB_SERVICE =>
        datasourceMetaInfoManager.getWebServiceModel(domId, dsAPI.dsId.get)
      case DisplayType.GUAN_FORM =>
        datasourceMetaInfoManager.getGuanFormModel(domId, dsAPI.dsId.get)
      case DisplayType.SFTP_FTP =>
        datasourceMetaInfoManager.getSftpFtpModel(domId, dsAPI, user)
      case DisplayType.AUGMENTED_ANALYSIS =>
        datasourceMetaInfoManager
          .getAugmentedAnalysisModel(domId, dsAPI.dsId.get)
          .map(x => Some(Json.obj("model" -> x)))
      case DisplayType.ADLS =>
        datasourceMetaInfoManager.getAdlsModel(domId, dsAPI, user)
      case DisplayType.ADLS_GEN2 =>
        datasourceMetaInfoManager.getAdlsGen2Model(domId, dsAPI, user)
      case x =>
        if (DisplayType.dbTypes.contains(x))
          datasourceMetaInfoManager.getConnectionModel(domId, dsAPI.dsId.get, user)
        else Future.successful(None)
    }
    r.map(_.map(_ ++ dsAPI.uniformResourceTypeJson()))
  }

  def get(dsId: String): Action[AnyContent] = SecuredGetAuthFromAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      val isAdmin = user.isAdmin
      (for {
        isOwner <- resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET)
        readable <- resourceAccChecker.canUseNonDirResource(user, dsId, TagRecordType.DATA_SET)
        res <-
          if (readable || isOwner || isAdmin) {
            datasourceMetaInfoManager.getWithColsIncludeAggregation(domId, dsId).flatMap {
              case Some(dsAPI: DataSourceAPI) =>
                val config = dsAPI.config.getOrElse(Json.obj())
                val sfTemplateId = (config \ "sfTemplateId").asOpt[String].getOrElse("")
                for {
                  modelInfo <- getModelInfo(user, dsAPI, Some(isAdmin || isOwner))
                  parentDirId = dsAPI.parentDirId.get
                  dirPath <- directories.getDirPath(domId, DirType.DATA_SET, parentDirId)
                  sfTemplateTable <- securityFilterTemplate.getTemplateTable(domId, sfTemplateId)
                  err <- resourceUpdateHistoryService.getErrorMsgWhenFailed(
                    domId,
                    dsId,
                    dsAPI.status.getOrElse(TaskStatus.FINISHED)
                  )
                  canExport <- resourceAccChecker.canExportResource(user, dsId, TagRecordType.DATA_SET)

                } yield {
                  val parentDirName = dirPath.lastOption.map(_._2).getOrElse("未知目录")
                  val newTemplateJson = if (sfTemplateTable.isDefined) {
                    Json.obj(
                      "sfTemplateId" -> sfTemplateId,
                      "sfTemplateName" -> JsString(sfTemplateTable.get.name.getOrElse(""))
                    )
                  } else {
                    Json.obj(
                      "sfTemplateId" -> "",
                      "sfTemplateName" -> ""
                    )
                  }
                  var newConfig = config.as[JsObject] - "sfTemplateId" + ("sfTemplate" -> newTemplateJson)

                  // 处理数据集token：不是admin、或者数据集owner，返回的数据要去掉token信息
                  if (!isOwner && !isAdmin) {
                    newConfig = newConfig - "tokenSetting"
                  } else {
                    val tokenSettingOpt = (newConfig \ "tokenSetting").asOpt[JsObject]
                    tokenSettingOpt.foreach { tokenSetting =>
                      val enabled = (tokenSetting \ "enabled").asOpt[Boolean].getOrElse(false)
                      // token功能没有启用，返回的信息要去掉token信息
                      if (!enabled) {
                        newConfig = newConfig - "tokenSetting"
                      }
                    }
                  }

                  val tableQuery = (config \ "tableQuery").asOpt[TableQueryDefinition]
                  if (tableQuery.exists(_.queryType == QueryType.TABLE)) {
                    newConfig = newConfig + ("tableQuery" -> Json.toJson(tableQuery.get.viewObject))
                  }

                  val newDsAPI = dsAPI.copy(config = Some(newConfig))
                  val res = Json.toJson(newDsAPI).as[JsObject] ++
                    Json.obj(
                      "parentDirName" -> parentDirName,
                      "dirPath" -> directories.createDirPathObj(dirPath),
                      "path" -> (dirPath.map(_._2).mkString(">") + s">${dsAPI.name}"),
                      "isOwner" -> isOwner,
                      "isAdmin" -> isAdmin,
                      "canExport" -> canExport
                    ) ++ modelInfo.getOrElse(Json.obj()) ++ err ++ newDsAPI.uniformResourceTypeJson()
                  SuccessResponse(res)
                }
              case _ =>
                errorResFuture(NotFoundException(traceData.getI18NMessage("NOT_FOUND.dataSourceNotFound")))
            }
          } else {
            datasourceMetaInfoManager.getBasicInfo(domId, dsId).map { res =>
              SuccessResponse(res.map {
                Json.toJson(_).as[JsObject] + ("hasPermission" -> JsBoolean(false))
              })
            }
          }
      } yield res).recover { case e: java.util.NoSuchElementException =>
        notFound("NOT_FOUND.datasetNotFound")
        logger.error(e.getMessage, e)
        ErrorResponse(ErrorResponse.NOT_FOUND, traceData.getI18NMessage("NOT_FOUND.datasetNotFound"))
      }
  }

  private def notFound(msg: String)(implicit traceData: TraceData) = errorResponse(NotFoundException(msg))

  def getStatus(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    request => implicit traceData: TraceData =>
      datasourceMetaInfoManager.getStatus(request.identity.get.domId.get, dsId).map {
        case Some(status) => SuccessResponse(status.toString)
        case _ => notFound("NOT_FOUND.datasetNotFound")
      }
  }

  def addColumn(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[FieldAPI](DatasetResource, UpdatePrivilege) { request => implicit traceData: TraceData =>
      val newField = request.body.trimName()
      val domId = request.identity.get.domId.get
      schemaManager.fieldContainsDesensitized(dsId, newField).flatMap {
        case false =>
          if (newField.isDerived) {
            val newFieldWithDecodeFormula =
              newField.copy(formula = newField.formula.map(x => Base64Util.decode(x, newField.ifEncoded)))
            for {
              res <- fields.addDerived(domId, dsId, newFieldWithDecodeFormula, dataSources, datasourceMetaInfoManager)
              // 更新data_source 表中config动态参数信息
              _ <- dataSources.updateDynamicParameter(domId, dsId, newFieldWithDecodeFormula.formula)
            } yield {
              if (res.isRight) {
                val dsName = res.right.get.name.getOrElse("")
                dataSources.taggedTraceDataForUserOperation(
                  domId,
                  dsId,
                  dsName,
                  AuditOpTypes.DsEditDataSetField,
                  Some(Json.toJson(newField).toString)
                )
                SuccessResponse(res.right.get)
              } else {
                ErrorResponse(ErrorResponse.INVALID_FORMULA, res.left.get)
              }
            }
          } else {
            fields.addPhysical(domId, dsId, newField).map { res =>
              if (res.isRight) {
                val dsName = res.right.get.name.getOrElse("")
                dataSources.taggedTraceDataForUserOperation(
                  domId,
                  dsId,
                  dsName,
                  AuditOpTypes.DsEditDataSetField,
                  Some(Json.toJson(newField).toString)
                )
                SuccessResponse(res.right.get)
              } else {
                ErrorResponse(ErrorResponse.NOT_UNIQUE, res.left.get)
              }
            }
          }
        case true =>
          Future.successful(
            ErrorResponse(
              ErrorResponse.UNKNOWN_ERROR,
              traceData.getI18NMessage("DESENSITIZATION.ContainsDesensitization")
            )
          )
      }
    }

  def updateColumn(dsId: String, fdId: String): Action[JsValue] =
    SecuredPostActionAsync[FieldAPI](DatasetResource, UpdatePrivilege) { request => implicit traceData: TraceData =>
      val updateField = request.body
      val domId = request.identity.get.domId.get
      val loginUser = request.identity.get

      if (updateField.isDerived) {
        val fieldWithDecodeFormula =
          updateField.copy(formula = updateField.formula.map(x => Base64Util.decode(x, updateField.ifEncoded)))
        for {
          // 更新data_source 表中config动态参数信息
          _ <- dataSources.updateDynamicParameter(domId, dsId, fieldWithDecodeFormula.formula)
          allCols <- datasourceMetaInfoManager.getWithColsIncludeAggregation(domId, dsId)
          originName = (allCols.get.columns.get ++ allCols.get.virtualColumns.get)
            .filter(_.fdId.get.equals(fdId))
            .head
            .name
          res <- fields.updateDerived(domId, dsId, fdId, fieldWithDecodeFormula, dataSources)
          _ <-
            if (!originName.get.equals(fieldWithDecodeFormula.name.get)) {
              // TODO 此处还不能同步类型。代码需要重构，统一「字段」的行为
              val assoc = Some(
                Seq(
                  FieldMap(
                    origFdId = Some(fdId),
                    origFdName = originName,
                    destFdId = Some(fdId),
                    destFdName = fieldWithDecodeFormula.name
                  )
                )
              )
              val fieldAssocAPI =
                FieldAssocAPI(destDsId = Some(dsId), assoc = assoc, cdIds = None, origDsId = Some(dsId))
              cardManipulate.batchChangeDataSet4Cards(loginUser, fieldAssocAPI)
            } else Future(Unit)
        } yield {
          if (res.isRight) {
            val dsName = res.right.get.name.getOrElse("")
            dataSources.taggedTraceDataForUserOperation(
              domId,
              dsId,
              dsName,
              AuditOpTypes.DsEditDataSetField,
              Some(Json.toJson(fieldWithDecodeFormula).toString)
            )
            SuccessResponse(res.right.get)
          } else {
            ErrorResponse(ErrorResponse.INVALID_FORMULA, res.left.get)
          }
        }
      } else {
        Future.successful(
          ErrorResponse(ErrorResponse.INVALID_FORMULA, traceData.getI18NMessage("INVALID_FORMULA.notDerivedField"))
        )
      }
    }

  def updateAlias(dsId: String, fdId: String): Action[JsValue] =
    SecuredPostActionAsync[JsObject](DatasetResource, UpdatePrivilege) { request => implicit traceData: TraceData =>
      val alias = (request.body \ "alias").asOpt[String]
      val domId = request.identity.get.domId.get

      fields
        .updateAlias(domId, dsId, fdId, alias)
        .map { _ =>
          dataSources.taggedTraceDataForUserOperationWithoutName(
            domId,
            dsId,
            AuditOpTypes.DsEditDataSetField,
            Some(Json.toJson(request.body).toString)
          )
          SuccessResponse("Ok")
        }
        .recover { case _: java.util.NoSuchElementException =>
          notFound("NOT_FOUND.fieldNotFound")
        }
    }

  def deleteColumn(dsId: String, fdId: String): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, UpdatePrivilege) { implicit request => implicit traceData: TraceData =>
      val domId = request.identity.get.domId.get
      fields
        .deleteDerived(domId, dsId, fdId)
        .map { res =>
          val dsName = res.flatMap(_.name).getOrElse("")
          dataSources.taggedTraceDataForUserOperation(domId, dsId, dsName, AuditOpTypes.DsEditDataSetField)
          SuccessResponse(res)
        }
        .recover { case _: java.util.NoSuchElementException =>
          ErrorResponse(
            ErrorResponse.INVALID_FORMULA,
            traceData.getI18NMessage("INVALID_FORMULA.cantdeleteColumnInUse")
          )
        }
    }

  def list(
      offset: Int,
      limit: Int,
      orderBy: String,
      uId: Option[String],
      displayType: Option[String],
      nameLike: Option[String],
      cnId: Option[String],
      acId: Option[String],
      hasDateField: Option[Boolean],
      permissionType: Option[String],
      desensitized: Option[Boolean] = None,
      needExport: Boolean
  ): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      val dType = displayType.map(DisplayType.withName)
      val pType = permissionType.map(PermissionType.withName).getOrElse(PermissionType.ALL)

      val dsFilter = DsFilter(
        domId = Some(domId),
        uId = uId,
        displayType = dType,
        searchKeyword = nameLike,
        acId = acId,
        parentDirId = None,
        desensitized = desensitized
      )
      val needAccountInfo = dType.isDefined && DisplayType.accountTypes.contains(dType.get)
      val isAdmin = user.isAdmin
      for {
        (count, res) <- datasourceMetaInfoManager.listByUserAndDomain(
          user,
          offset,
          limit,
          orderBy,
          dsFilter,
          hasDateField,
          Some(pType)
        )
        accountInfo <-
          if (needAccountInfo)
            accounts.getByUIdAndAcIds(user.uId.get, res.flatMap(_.acId.toList))
          else Future.successful(Nil)
        resWithPrivilegeInfo <- FutureUtil.serialiseFutures(res) { ds =>
          for {
            isOwner <- resourceAccChecker.canManageNonDirResource(user, ds.dsId.get, TagRecordType.DATA_SET)
            canExport <-
              if (needExport) {
                resourceAccChecker.canExportResource(user, ds.dsId.get, DATA_SET).map(Option(_))
              } else Future.successful(None)
            dirPath <- directories.getDirPath(domId, DirType.DATA_SET, ds.parentDirId.get)
            isAcc = ds.config.exists { config => (config \ "acc").asOpt[Boolean].getOrElse(false) }
          } yield {
            val canManage = isAdmin || isOwner
            val res = Json.toJson(ds).as[JsObject] + ("canManage" -> JsBoolean(canManage)) + ("isAcc" -> JsBoolean(
              isAcc
            )) + ("dirPath" -> JsArray(directories.createDirPathObj(dirPath))) + ("readableAndOwners" -> Json
              .obj()) ++ ds
              .uniformResourceTypeJson() ++ Json.obj("path" -> (dirPath.map(_._2).mkString(">") + s">${ds.name}"))
            val resWithExtraInfo = if (canExport.isDefined) res + ("canExport" -> JsBoolean(canExport.get)) else res
            resWithExtraInfo
          }
        }
      } yield {
        val userInfos = resWithPrivilegeInfo.foldLeft(Map[String, JsValue]()) { (m, s) =>
          m + ((s \ "uId").as[String] -> (s \ "readableAndOwners" \ "ownerUsers" \ 0)
            .getOrElse(Json.obj("name" -> "no find")))
        }
        val resp = Json.obj(
          "totalCount" -> count,
          "dataSources" -> resWithPrivilegeInfo,
          "userInfo" -> userInfos,
          "accounts" -> accountInfo
        )
        SuccessResponse(resp)
      }
  }

  def clearAll(domId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, ManagePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      dataSources.clearAll(domId).map { success =>
        if (success) {
          traceData.logger.warn(s"User ${user.name} ${user.uId} delete all data sources of domain $domId")
          SuccessResponse("Success")
        } else {
          ErrorResponse(ErrorResponse.UNKNOWN_ERROR, "Failed to delete some of the data sources")
        }
      }
  }

  def cleanStorageOfDeletedDs(): Action[AnyContent] = SecuredActionAsync(DatasetResource, ManagePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      storageManager.cleanStorageOfDeletedDs(user.domId.get).map { _ =>
        SuccessResponse("Finished")
      }
  }

  def listDeletedDsNotCleaned(): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      storageManager.listDeletedDsNotCleaned(user.domId.get).map { res =>
        SuccessResponse(res)
      }
  }

  def getDomainCompleteTreedDatasets(): Action[AnyContent] = SecuredActionAsync(BaseResource, UpdatePrivilege) {
    implicit request => implicit traceData: TraceData =>
      dataSources.getDatasetsTreeForAdmin(request.logonUser).map(SuccessResponse(_))
  }

  def getAuthorizedDatasetsTree(): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      dataSources.getDatasetsTree(request.logonUser).map(SuccessResponse(_))
  }

  def batchDelete(): Action[JsValue] = SecuredPostActionAsync[JsObject](DatasetResource, DeletePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val dsIdsOpt: Option[Seq[String]] = (request.body \ "dsIds").asOpt[Seq[String]]
      if (dsIdsOpt.isDefined && dsIdsOpt.get.nonEmpty) {
        val deletableCount = config.datasetDeleteCountLimit
        if (dsIdsOpt.get.size > deletableCount) {
          Future.successful(
            ErrorResponse(
              ErrorResponse.DELETE_ERROR,
              traceData.getI18NMessage("DELETE_ERROR.deleteCountExceed", deletableCount)
            )
          )
        } else {
          val results = FutureUtil.serialiseFutures(dsIdsOpt.get)(dsId => dataSources.doDelete(dsId, user))
          results.map { res =>
            val failedCount = res.count(_.isDefined)
            if (failedCount.equals(0)) {
              SuccessResponse(
                traceData.getI18NMessage("DATA_SOURCE.deleteSuccess", res.size.toString)
              )
            } else {
              ErrorResponse(
                ErrorResponse.DEPENDENCY_EXIST,
                traceData.getI18NMessage("DEPENDENCY_EXIST.DatasourceDeleteFailed", failedCount.toString)
              )
            }
          }
        }
      } else {
        Future.successful(notFound("NOT_FOUND.noDatasourceToDelete"))
      }
  }

  def delete(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, DeletePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      dataSources.doDelete(dsId, user).map {
        _.map { case (errCode: Int, errMsg: String) =>
          ErrorResponse(errCode, errMsg)
        }.getOrElse(SuccessResponse("DataSource deleted"))
      }
  }

  def getCards(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      cards
        .getCardsByDsId(dsId, request.identity.get, pages, PageQueryRequest(true))
        .map(res => SuccessResponse(Json.obj("readableCards" -> res._1, "unReadableCnt" -> res._2)))
  }

  /**
   * 分页查询数据集的卡片； 由于界面展示是按page进行分组展示的，所以分页查询也是针对的是page，而不是card
   * @param dsId
   *   数据集id
   * @param offset
   *   偏移量
   * @param limit
   *   页面加载数量
   */
  def searchCards(dsId: String, offset: Int, limit: Int, category: Option[String]): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      cards
        .getCardsByDsId(dsId, request.identity.get, pages, PageQueryRequest(false, offset, limit), category)
        .map(res =>
          SuccessResponse(
            Json.obj(
              "readableCards" -> res._1,
              "unReadableCnt" -> res._2,
              "pageTotal" -> res._3,
              "limit" -> limit,
              "offset" -> offset
            )
          )
        )
    }

  /**
   * 获取和这个数据集相关联的etl、fusion、和实时数据集。老的方法将被替代：getDataFlowsAndFusions
   *
   * @param dsId
   * @return
   */
  def getAssociations(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      for {
        dataFlowsWithReadableFlag <- smartETLQueryService.getByInputDsId(domId, dsId).flatMap { dataFlowList =>
          FutureUtil.serialiseFutures(dataFlowList) { dataFlow =>
            resourceAccChecker
              .canUseNonDirResource(user, dataFlow.etlId, TagRecordType.DATA_FLOW)
              .map(dataFlow -> _)
          }
        }
        fusionsWithReadableFlag <- dataSources.getChildDsWithReadableFlag(domId, dsId, user, DisplayType.DATAFUSION)

        // 相关的实时数据集，使用这个数据集作为附加属性
        rtDataSources <- rtDsService.getDataSourcesByLookupDsId(dsId).flatMap { dsList =>
          FutureUtil.serialiseFutures(dsList) { ds =>
            resourceAccChecker
              .canUseNonDirResource(user, ds.dsId.get, TagRecordType.DATA_SET)
              .map(ds -> _)
          }
        }

        sparkViewsWithReadableFlag <- dataSources.getChildDsWithReadableFlag(domId, dsId, user, DisplayType.SPARK_VIEW)
      } yield {
        val (readableDataFlows, unReadableDataFlows) = dataFlowsWithReadableFlag.partition(_._2)
        val (readableFusions, unReadableFusions) = fusionsWithReadableFlag.partition(_._2)
        val (readableRtDataSources, unReadableRtDataSources) = rtDataSources.partition(_._2)
        val (readableSparkViews, unReadableSparkViews) = sparkViewsWithReadableFlag.partition(_._2)
        val resJsonObj = Json.obj(
          "dataflows" ->
            Json.obj(
              "readable" -> readableDataFlows.map(_._1).map(Json.toJson(_)),
              "unReadableCnt" -> unReadableDataFlows.length
            ),
          "fusions" ->
            Json.obj(
              "readable" -> readableFusions.map(_._1).map(Json.toJson(_)),
              "unReadableCnt" -> unReadableFusions.length
            ),
          "realtime" ->
            Json.obj(
              "readable" -> readableRtDataSources.map(_._1).map(Json.toJson(_)),
              "unReadableCnt" -> unReadableRtDataSources.length
            ),
          "sparkViews" ->
            Json.obj(
              "readable" -> readableSparkViews.map(_._1).map(Json.toJson(_)),
              "unReadableCnt" -> unReadableSparkViews.length
            )
        )
        SuccessResponse(resJsonObj)
      }
  }

  def getDataFlowsAndFusions(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      for {
        dataFlowsWithReadableFlag <- smartETLQueryService.getByInputDsId(domId, dsId).flatMap { dataFlowList =>
          FutureUtil.serialiseFutures(dataFlowList) { dataFlow =>
            resourceAccChecker
              .canUseNonDirResource(user, dataFlow.etlId, TagRecordType.DATA_FLOW)
              .map(dataFlow -> _)
          }
        }
        fusionsWithReadableFlag <- datasourceMetaInfoManager.getChildDsByDsId(domId, dsId).flatMap { fusionDsList =>
          FutureUtil.serialiseFutures(fusionDsList) { fusionDs =>
            resourceAccChecker
              .canUseNonDirResource(user, fusionDs.dsId.get, TagRecordType.DATA_SET)
              .map(fusionDs -> _)
          }
        }
      } yield {
        val (readableDataFlows, unReadableDataFlows) = dataFlowsWithReadableFlag.partition(_._2)
        val (readableFusions, unReadableFusions) = fusionsWithReadableFlag.partition(_._2)
        val resJsonObj = Json.obj(
          "dataflows" ->
            Json.obj(
              "readable" -> readableDataFlows.map(_._1).map(Json.toJson(_)),
              "unReadableCnt" -> unReadableDataFlows.length
            ),
          "fusions" ->
            Json.obj(
              "readable" -> readableFusions.map(_._1).map(Json.toJson(_)),
              "unReadableCnt" -> unReadableFusions.length
            )
        )

        SuccessResponse(resJsonObj)
      }
  }

  def createFromAccount: Action[JsValue] =
    SecuredPostActionAsync[CreateDsFromAccountQuery](DatasetResource, CreatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val params = request.body
        dataSources.createFromAccount(user, params).map(_.toResult)
    }

  def createFromAPI: Action[JsValue] =
    SecuredPostActionAsync[QueryParamOfCreateDsAPI](DatasetResource, CreatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val params = request.body
        dataSources.createFromAPI(user, params).map(_.toResult)
    }

  def createFromFtp: Action[JsValue] = SecuredPostActionAsync[CreateDsFromFtpQuery](DatasetResource, CreatePrivilege) {
    request => implicit traceData: TraceData =>
      val user = request.identity.get
      val params = request.body
      dataSources.createFromFtp(user, params).map(_.toResult)
  }

  def createFromAdlsForDatabricks: Action[JsValue] =
    SecuredPostActionAsync[CreateDsFromAdlsQuery](DatasetResource, CreatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val params = request.body
        dataSources.createFromAdlsForDatabricks(user, params).map(_.toResult)
    }

  def createFromAdlsGen2: Action[JsValue] =
    SecuredPostActionAsync[CreateDsFromAdlsGen2Query](DatasetResource, CreatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val params = request.body
        dataSources.createFromAdlsGen2(user, params).map(_.toResult)
    }

  def previewAdlsGen2DataAsync(): Action[JsValue] =
    SecuredPostActionAsync[AdlsGen2FileQuery](DatasetResource, ReadPrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val backendAddress = clusteringService.getBackendAddress().getOrElse("")
        accounts
          .getAccountByAcId(user.domId.get, request.body.acId)
          .flatMap { account =>
            {
              if (account.isEmpty) {
                Future.successful(
                  ErrorResponse(
                    ErrorResponse.SERVER_ERROR,
                    traceData.getI18NMessage("SERVER_ERROR.accountFailed")
                  )
                )
              } else {
                val taskParams = Map(
                  TaskParam.TRACE_ID -> traceData.traceId.getOrElse(""),
                  TaskParam.DESC -> s"Preview Data for adls gen2"
                )
                val task = new PreviewAdlsGen2Task(
                  TaskType.ADLS_GEN2_DATASET,
                  taskParams,
                  azureService,
                  user,
                  account.get,
                  request.body,
                  backendAddress
                )
                jobManager.triggerTask(user.domId.get, Seq(task)).map(_ => task.taskInfo.taskId.toResponse)
              }
            }
          }
    }

  def batchChangeDirectory(): Action[JsValue] =
    SecuredPostActionAsync[BatchChangeDirectoryRequest](DatasetResource, UpdatePrivilege) {
      implicit request => implicit traceData: TraceData =>
        val user = request.logonUser
        val domId = user.domainId
        val body = request.body
        val (newParentDirId, dsIds) = (body.parentDirId, body.dsIds)
        dsIds.foreach(
          dataSources.taggedTraceDataForUserOperationWithoutName(
            domId,
            _,
            AuditOpTypes.DsBatchMoveDataSet,
            Json.toJson(request.body).toString().ofOptional
          )
        )
        FutureUtil
          .serialiseFutures(dsIds)(dsId =>
            dataSourceUpdateProperties.changeDirectoryWithUserAuth(user, dsId, newParentDirId)
          )
          .flatMap(_ => directories.getDirInfo(domId, user, DirType.DATA_SET, newParentDirId).map(SuccessResponse(_)))
    }

  def changeDirectory(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[JsObject](DatasetResource, UpdatePrivilege) {
      implicit request => implicit traceData: TraceData =>
        val newParentDirId = (request.body \ "parentDirId").as[String]
        val user = request.identity.get
        dataSourceUpdateProperties.changeDirectoryWithUserAuth(user, dsId, newParentDirId).flatMap { _ =>
          dataSources.taggedTraceDataForUserOperationWithoutName(
            request.identity.get.domId.get,
            dsId,
            AuditOpTypes.DsMoveDataSet,
            Some(Json.toJson(request.body).toString)
          )
          directories
            .getDirInfo(user.domId.get, user, DirType.DATA_SET, newParentDirId)
            .map(SuccessResponse(_))
        }
    }

  /**
   * 校验输出数据集的目录权限 - 仅限etl编辑及新建时使用
   * @param dataFlowId
   * -值为空，则以登陆人身份校验目录权限
   * -不为空，则以etl所有者身份校验目录权限
   * @param dsName
   *   输出数据集名称
   * @param dsId
   * -值为空，以登陆人身份校验目录权限
   * -值不为空，以etl所有者身份校验目录权限
   * @param dirId
   *   输出数据集保存目录id
   * @return
   */
  def checkDirAuthOfOutDs(
      dataFlowId: Option[String],
      dsName: String,
      dsId: Option[String],
      dirId: Option[String]
  ): Action[AnyContent] =
    SecuredActionAsync(BaseResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      val loginUser = request.identity.get
      val domId = loginUser.domId.get
      dataSources.checkDirAuthOfOutDs(dirId, domId, loginUser, dataFlowId, dsName, dsId).map { checkResult =>
        SuccessResponse(Json.obj("dsId" -> dsId, "checkResult" -> checkResult))
      }
    }

  /*
   *  deprecated, 请用 refresh 来刷新各种数据源
   */
  def forceRefresh(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, UpdatePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      datasourceMetaInfoManager.syncUpdateVersion(domId, dsId).map { _ =>
        dataSourceUpdate.dsFullUpdate(user.domId.get, dsId)
        dataSources.taggedTraceDataForUserOperationWithoutName(domId, dsId, AuditOpTypes.DsUpdateDataSet)
        SuccessResponse("success")
      }
  }

  def forceRefreshCard(cdId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, UpdatePrivilege) {
    implicit request => implicit traceData: TraceData =>
      dataSourceUpdate.cardRefresh(request.identity.get.domId.get, cdId).map { _ =>
        SuccessResponse("success")
      }
  }

  private def formatTimestamp(ts: Timestamp) = {
    new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ").format(ts)
  }

  private def convertDsUtimeTuple(tuples: Seq[(String, Option[String], Option[Timestamp])]) = {
    tuples.map { case (dsId, name, utime) =>
      Json.obj("dsId" -> dsId, "name" -> name, "utime" -> formatTimestamp(utime.get))
    }
  }

  private def convertCardUtimeTuple(tuples: Seq[(String, String, Option[Timestamp])]) = {
    tuples.map { case (dsId, name, utime) =>
      Json.obj("dsId" -> dsId, "name" -> name, "utime" -> formatTimestamp(utime.get))
    }
  }

  def checkAffectedCardAndDatasetsUpdateTime(dsId: String): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ManagePrivilege) { implicit request => implicit traceData: TraceData =>
      val affectedDsIds = datasourceMetaInfoManager.getCascadeUpdates(dsId)
      for {
        origUtime <- datasourceMetaInfoManager.getLastUpdateTime(Seq(dsId))
        affectedUtime <- datasourceMetaInfoManager.getLastUpdateTime(affectedDsIds)
        origDsUpdateTime = origUtime.head._3.get
        (failed, success) = affectedUtime.partition { case (_, _, childUtime) =>
          childUtime.get.before(origDsUpdateTime)
        }
        cardUtime <- cards.getLastUpdateTimeByDsIds(success.map(_._1))
        failedCards = cardUtime.filter(_._3.get.before(origDsUpdateTime))
      } yield {
        val res = Json.obj(
          "sourceUpdateTime" -> formatTimestamp(origDsUpdateTime),
          "notUpdatedDs" -> convertDsUtimeTuple(failed),
          "notUpdatedCard" -> convertCardUtimeTuple(failedCards)
        )
        SuccessResponse(res)
      }
    }

  def autoUpdateDistribution(sourceType: String): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      dataSources.autoUpdateDistributionAnalyse(sourceType).map { result =>
        SuccessResponse(result)
      }
    }

  def changeTablePrimaryKey(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[JsObject](DatasetResource, UpdatePrivilege) { request => implicit traceData: TraceData =>
      val domId = request.identity.get.domId.get
      val keyColumns = (request.body \ "keyColumns").as[Seq[String]]
      val user = request.identity.get

      canDataSourceChangePrimaryKeys(domId, dsId).flatMap {
        case true =>
          resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET).flatMap {
            case true =>
              datasourceMetaInfoManager.getWithPhysicalCols(domId, dsId).flatMap {
                case Some(dataSourceAPI) =>
                  if (dataSourceAPI.displayType == DisplayType.PUBLIC) {
                    Future.successful(
                      ErrorResponse(
                        INVALID_DATA_SOURCE,
                        traceData.getI18NMessage("INVALID_DATA_SOURCE.cantModifyPKOfSharedDataset"),
                        NotifyType.VALIDATE
                      )
                    )
                  } else {
                    isDataSourceProcessing(domId, dsId).flatMap {
                      case true =>
                        Future.successful(
                          ErrorResponse(
                            ErrorResponse.SERVER_ERROR,
                            traceData.getI18NMessage("SERVER_ERROR.changePrimaryKeysFailed")
                          )
                        )
                      case false =>
                        dataSources.changePrimaryKeys(domId, user, dataSourceAPI, keyColumns).map { tuple =>
                          dataSources.taggedTraceDataForUserOperationWithoutName(
                            domId,
                            dsId,
                            AuditOpTypes.DsEditDataSet,
                            Some(Json.toJson(request.body).toString)
                          )
                          SuccessResponse(tuple._1)
                        }
                    }
                  }
                case _ => Future.successful(notFound("NOT_FOUND.datasetNotFound"))
              }
            case false =>
              Future.successful(
                ErrorResponse(
                  ErrorResponse.PERMISSION_DENIED,
                  traceData.getI18NMessage("PERMISSION_DENIED.permissionDenied")
                )
              )
          }
        case false =>
          Future.successful(
            ErrorResponse(
              ErrorResponse.SERVER_ERROR,
              traceData.getI18NMessage("SERVER_ERROR.dataSourceChangePrimaryKeysFailed")
            )
          )
      }
    }

  def assocCron(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[CronDefinition](DatasetResource, UpdatePrivilege) {
      request => implicit traceData: TraceData =>
        val domId = request.identity.get.domId.get
        val cronType = request.body.cronType
        val cronValue = request.body.value.getOrElse("")

        dataSourceUpdate.assocCronShared(domId = domId, dsId = dsId, cronType = cronType, cronValue = cronValue)
    }

  def clearCron(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, UpdatePrivilege) {
    request => implicit traceData: TraceData =>
      val domId = request.identity.get.domId.get
      datasourceMetaInfoManager.clearCron(domId, dsId).map { _ =>
        SuccessResponse("OK")
      }
  }

  /**
   * 以后会用这个 API 来代替 forceRefresh guanIndex改造后，逐渐被triggerRefresh替用
   */
  def refresh(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, UpdatePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      datasourceMetaInfoManager.get(domId, dsId).flatMap {
        case Some(dsAPI) if DisplayType.unSupportedTriggerUpdate.contains(dsAPI.displayType) || dsAPI.isApiWorkBench =>
          errFuture(INVALID_DATA_SOURCE, "INVALID_DATA_SOURCE.unSupportedTriggerUpdate")()
        case None =>
          Future.successful(notFound("NOT_FOUND.datasetNotFound"))
        case _ =>
          dataSourceUpdate.triggerUpdate(domId, dsId, request.identity).map { res =>
            dataSources.taggedTraceDataForUserOperationWithoutName(domId, dsId, AuditOpTypes.DsUpdateDataSet)
            res.toResult
          }
      }
  }

  def originInfoRefresh(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, UpdatePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      for {
        dsOpt <- datasourceMetaInfoManager.getWithCols(domId, dsId)
        res <- schemaManager.syncDSFieldAnnotationFromOriginSource(dsOpt)
      } yield {
        if (res.isLeft) {
          ErrorResponse(ErrorResponse.SERVER_ERROR, traceData.getI18NMessage("SERVER_ERROR.getOriginSourceInfoFailed"))
        } else {
          SuccessResponse(Json.obj("columns" -> Json.toJson(res.right.get)))
        }
      }
  }

  /**
   * 工具项更新调用updateGuanIndex，这里的更新方式与原数据集无关，原来数据集没有设置增量，这里可以设置成增量；
   * 原来数据集设置成了增量，这里也可以设置成不用增量，根据overwriteExistingData覆盖"enabled"字段
   *
   * @param dsId
   *   dataSourceId
   * @return
   */
  def triggerRefresh(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataTriggerRefreshQuery](DatasetResource, UpdatePrivilege) {
      clusteringService.forwardPostToMaster { implicit request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domId.get
        val queryOpt =
          if (request.body.ifEncoded.contains(true))
            request.body.query.map(q => new String(java.util.Base64.getDecoder.decode(q), StandardCharsets.UTF_8))
          else request.body.query
        val overwriteExistingData = request.body.overwriteExistingData
        updateDs(
          user,
          domId,
          dsId,
          overwriteExistingData,
          queryOpt,
          Some(request.body)
        ).map {
          dataSources.taggedTraceDataForUserOperationWithoutName(
            domId,
            dsId,
            AuditOpTypes.DsUpdateDataSet,
            Some(Json.toJson(request.body).toString)
          )
          _.toResult
        }
      }
    }

  def batchUpdate(): Action[JsValue] = SecuredPostActionAsync[JsArray](DatasetResource, UpdatePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      val dsIds = request.body.asOpt[List[String]].getOrElse(List())

      val futureRes = dsIds.map(dsId => updateDs(user, domId, dsId).map(dsId -> _))

      FutureUtil
        .serialiseFutures(futureRes) {
          _.map { res =>
            dataSources.taggedTraceDataForUserOperationWithoutName(
              domId,
              res._1,
              AuditOpTypes.DsBatchUpdateDataSet
            )
            res
          }
        }
        .map(list => {
          // GALAXY-5361; 批量更新数据集，连续更新报错
          val finalRes: List[JsObject] = list
            .filter(filterRes => StringUtils.equals(filterRes._2.result, EndpointResponse.OK))
            .map(transformRes => Json.obj("dsId" -> transformRes._1) ++ transformRes._2.response.as[JsObject])

          SuccessResponse(finalRes)
        })
  }

  def batchOverwriteExistingData(): Action[JsValue] =
    SecuredPostActionAsync[JsValue](DatasetResource, UpdatePrivilege) {
      implicit request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domId.get
        val isRefreshAll = (request.body \ "isRefreshAll").asOpt[Boolean].getOrElse(false)
        val dsIds = (request.body \ "dsIds").asOpt[List[String]].getOrElse(List())

        val callBack = () => {
          val dsAPIsFuture = if (isRefreshAll) {
            datasourceMetaInfoManager.getAllDataSourceInfos(domId)
          } else {
            datasourceMetaInfoManager.batchGetInfo(dsIds.toSet)
          }

          dsAPIsFuture.flatMap(dsAPIs => {
            val futureRes = dsAPIs
              .filter(dsAPI =>
                dsAPI.config.isDefined &&
                  "GUAN_INDEX".equals((dsAPI.config.get \ "sourceType").asOpt[String].getOrElse("")) &&
                  (dsAPI.config.get \ "tableQuery").isDefined &&
                  (dsAPI.config.get \ "tableQuery" \ "query").asOpt[String].isDefined
              )
              .map(dsAPI => {
                val sql = (dsAPI.config.get \ "tableQuery" \ "query").as[String]
                val dsId = dsAPI.dsId.get
                updateDs(user, domId, dsId, Option(true), Option(sql), None).map(dsId -> _)
              })

            FutureUtil
              .serialiseFutures(futureRes) {
                _.map { res =>
                  Json.obj("dsId" -> res._1) ++ res._2.response.as[JsObject]
                }
              }
              .map(list => SuccessResponse(list))
          })
        }

        val traceId = traceData.traceId.getOrElse("")
        val taskParamsMap = Map(
          TaskParam.TRACE_ID -> traceId,
          TaskParam.DESC -> s"batch update datasources.",
          TaskParam.OBJECT_NAME -> "",
          TaskParam.USER_NAME -> "自动更新"
        )
        val task = new SimpleTask(TaskType.GUANINDEX, taskParamsMap, callBack)
        jobManager
          .triggerTask(domId, Seq(task))
          .map { _ =>
            val submitResult = Json.obj("taskId" -> task.taskInfo.taskId.toString)
            SuccessResponse(submitResult)
          }
    }

  private def updateDs(
      user: UserAPI,
      domId: String,
      dsId: String,
      overwriteExistingData: Option[Boolean] = None,
      queryOpt: Option[String] = None,
      refreshQuery: Option[DataTriggerRefreshQuery] = None
  )(implicit traceData: TraceData): Future[EndpointResponse] = {
    resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET).flatMap {
      case true =>
        isDataSourceProcessing(domId, dsId).flatMap {
          case true =>
            Future.successful(
              ErrorResponseInternal(
                ErrorResponse.SERVER_ERROR,
                traceData.getI18NMessage("SERVER_ERROR.updateDataSetFailed")
              )
            )
          case false =>
            val (webServiceUpdateConfig, refreshTableList, ftpUpdateConfig, adlsGen2UpdateConfig) =
              if (refreshQuery.isDefined) {
                (
                  refreshQuery.get.webServiceUpdateConfig,
                  refreshQuery.get.refreshTableList,
                  refreshQuery.get.ftpUpdateConfig,
                  refreshQuery.get.adlsGen2UpdateConfig
                )
              } else {
                (None, None, None, None)
              }
            datasourceMetaInfoManager.getConfig(domId, dsId).flatMap { dsConfig =>
              val sourceType = (Json.parse(dsConfig.get) \ "sourceType").asOpt[String].getOrElse("")
              if (sourceType == DataSourceOriginSourceType.GUAN_INDEX.toString) {
                datasourceMetaInfoManager.getWithPhysicalCols(domId, dsId).flatMap { dataSourceAPIOpt =>
                  val dataSourceAPI = dataSourceAPIOpt.get
                  val originSetting = (dataSourceAPI.config.get \ "guanIndexIncrementalUpdateSetting")
                    .asOpt[GuanIndexIncrementalUpdateSetting]
                    .getOrElse(GuanIndexIncrementalUpdateSetting(enabled = false, query = ""))

                  val guanIndexIncrementalUpdateSetting = overwriteExistingData
                    .map {
                      case true => originSetting.copy(enabled = false)
                      case false => originSetting.copy(enabled = true)
                    }
                    .getOrElse(originSetting)
                    .copy(webServiceUpdateConfig = webServiceUpdateConfig)
                    .copy(ftpUpdateConfig = ftpUpdateConfig)
                    .copy(adlsGen2UpdateConfig = adlsGen2UpdateConfig)
                  val configNew = dataSourceAPI.config.get.as[JsObject] +
                    ("guanIndexIncrementalUpdateSetting", Json.toJson(guanIndexIncrementalUpdateSetting).as[JsValue])
                  val dataSourceAPINew = dataSourceAPI.copy(config = Option(configNew))
                  guanIndexUpdateManager
                    .updateGuanIndex(dataSourceAPINew, queryOpt, Option(user), refreshTableList = refreshTableList)
                }
              } else dataSourceUpdate.triggerUpdate(domId, dsId, Option(user))
            }
        }
      case false =>
        Future.successful(
          ErrorResponseInternal(
            ErrorResponse.PERMISSION_DENIED,
            traceData.getI18NMessage("PERMISSION_DENIED.permissionDenied")
          )
        )
    }
  }

  private def isDataSourceProcessing(domId: String, dsId: String)(implicit traceData: TraceData) =
    datasourceMetaInfoManager.getStatus(domId, dsId).map { status =>
      if (TaskStatus.runningStatusForDataSource.contains(status.getOrElse(TaskStatus.FINISHED))) {
        val runtimeInfo = jobManager.customQueryByRuntimeInfo(Some(domId))
        runtimeInfo.workingTasks.exists(_.objectId.contains(dsId))
      } else false
    }

  def copyDataset: Action[JsValue] = SecuredPostActionAsync[JsObject](DatasetResource, ManagePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val origDomId = (request.body \ "origDomId").as[String]
      val origDsId = (request.body \ "origDsId").as[String]
      val targetUId = (request.body \ "targetUId").as[String]
      val targetDomId = (request.body \ "targetDomId").as[String]
      datasourceMetaInfoManager.get(origDomId, origDsId).flatMap { ds =>
        val newDsId = RandUtil.uuid
        val dsApi = DataSourceAPI(
          dsId = Some(newDsId),
          storageId = Some(newDsId),
          name = ds.get.name,
          displayType = ds.get.displayType,
          uId = Some(targetUId),
          domId = Some(targetDomId),
          cnId = ds.get.cnId,
          acId = ds.get.acId
        )
        dataSources.copyDataset(origDomId, origDsId, fields, dsApi).map { newDsId =>
          SuccessResponse(newDsId)
        }
      }
  }

  def getDisplayTypes: Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      datasourceMetaInfoManager.getDisplayTypesByDomain(request.identity.get.domId.get).map(SuccessResponse(_))
  }

  def saveAs(dsId: String): Action[JsValue] = SecuredPostActionAsync[JsObject](DatasetResource, CreatePrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      val uId = user.uId.get
      val dsName = (request.body \ "newDsName").as[String]
      val parentDirIdOpt = (request.body \ "parentDirId").asOpt[String]

      dataSourceUpdateProperties.checkDirOfDsToErrMsg(domId, None, parentDirIdOpt, dsName).flatMap {
        case Left((errCode, errMsg)) =>
          Future.successful(ErrorResponse(errCode, errMsg))
        case Right(_) =>
          doSaveAs(user, dsId, uId, dsName, parentDirIdOpt).flatMap { res =>
            dataSources.taggedTraceDataForUserOperationWithoutName(domId, dsId, AuditOpTypes.DsSaveDataSet)
            resourceAccUpdater.updateParentDirVisitors(domId, parentDirIdOpt.get, DirType.DATA_SET).map(_ => res)
          }
      }
  }

  private def doSaveAs(user: UserAPI, dsId: String, uId: String, dsName: String, parentDirIdOpt: Option[String])(
      implicit traceData: TraceData
  ): Future[Result] = {
    val domId = user.domId.get
    resourceAccChecker.canUseDirectory(user, parentDirIdOpt.get, DirType.DATA_SET).flatMap {
      case true =>
        for {
          domain <- domainService.getSettings(domId)
          dsSettingsOpt <- dataSourcesSettings.get(domId, dsId)
          dsAPI <- datasourceMetaInfoManager.get(domId, dsId)
          isAcPermission <- dataSources.checkDsAccountPermission(user, dsAPI.get)
          x <- dsSettingsOpt match {
            case None if domain.datasetAsDatasetFeatureEnabled =>
              val rowLimit = domain.rowLimit
              dsAPI match {
                case Some(ds) if isAcPermission.isLeft =>
                  errFuture(ErrorResponse.INVALID_DATA_SOURCE, isAcPermission.left.get)()
                case Some(ds) if !ds.isDirectDB && !ds.isSaveAsWithNoData && ds.exceedRowLimit(rowLimit) =>
                  errFuture(INVALID_DATA_SOURCE, "INVALID_DATA_SOURCE.exceedTheRowLimit", rowLimit)()
                case Some(ds) if ds.isSparkView =>
                  sparkViewService.saveAs(domId, uId, ds, dsName, parentDirIdOpt).map(SuccessResponse(_))
                case Some(ds) =>
                  val newDsId = RandUtil.uuid
                  val newDs = ds.copy(
                    dsId = Some(newDsId),
                    storageId = Some(newDsId),
                    name = dsName,
                    uId = Some(uId),
                    domId = Some(domId),
                    parentDirId = parentDirIdOpt,
                    version = Option(0),
                    cardCount = Option(0)
                  )
                  val copyFuture = if (ds.isDirectDB) {
                    fields
                      .getByDsIdIncludeAggregation(ds.dsId.get)
                      .flatMap(fieldAPIs =>
                        datasourceMetaInfoManager.createDataset(newDs, fieldAPIs.map(_.copy(dsId = Some(newDsId))))
                      )
                  } else {
                    val guanIndexDs =
                      if (ds.displayType == DisplayType.DATAFLOW)
                        newDs.copy(displayType = DisplayType.EXCEL)
                      else newDs
                    if (ds.isSaveAsWithNoData) {
                      var newConfig = ds.config.get.asOpt[JsObject].getOrElse(Json.obj())
                      newConfig = newConfig - "taskId" - "lastExecution"
                      fields
                        .getByDsIdIncludeAggregation(ds.dsId.get)
                        .flatMap(fieldAPIs =>
                          guanIndexDs.displayType match {
                            case DisplayType.REAL_TIME =>
                              rtDsService.saveAs(
                                oldDs = ds,
                                newDs = guanIndexDs,
                                fieldAPIs = fieldAPIs.map(_.copy(dsId = Some(newDsId))),
                                uId = uId
                              )
                            case _ =>
                              datasourceMetaInfoManager.createDataset(
                                guanIndexDs.copy(config = Some(newConfig), rowCount = Some(0)),
                                fieldAPIs.map(_.copy(dsId = Some(newDsId)))
                              )
                          }
                        )
                    } else {
                      dataSources.copyDataset(domId, dsId, fields, guanIndexDs)
                    }
                  }
                  copyFuture
                    .map { _ =>
                      if (ds.dataCronInfo.isDefined) {
                        val cronInfo = ds.dataCronInfo.get
                        dataSourceUpdate.assocCronShared(domId, newDsId, cronInfo.cronType, cronInfo.value)
                      }
                      desensitizationRuleService.copyRule(domId, ds.dsId.get, newDsId)
                      val templateId = (ds.config.get \ SecurityFilterSwitchConfigName.SECURITY_FILTER_TEMPLATE)
                        .asOpt[String]
                        .getOrElse("")
                      fields.getByDsIdIncludeAggregation(newDsId).flatMap { fieldAPISeq =>
                        securityFilterTemplateService.copySecurityFilter(
                          domId,
                          templateId,
                          ds.dsId.get,
                          newDsId,
                          fieldAPISeq
                        )
                      }

                    }
                    .map(_ => SuccessResponse(newDsId))
                    .recoverWith { case e: Exception =>
                      errFuture(INVALID_DATA_SOURCE, "INVALID_DATA_SOURCE.cantCopyDateSetbetweenDifferentBackends")()
                    }
              }
            case None =>
              errFuture(ErrorResponse.PERMISSION_DENIED, "PERMISSION_DENIED.permissionDenied")()
            case Some(_) =>
              errFuture(INVALID_DATA_SOURCE, "INVALID_DATA_SOURCE.cantSaveAsEncryptData")()
          }
        } yield x
      case false =>
        errFuture(INVALID_PARAMETERS, "INVALID_PARAMETERS.invalidSavePath")(NotifyType.VALIDATE)
    }
  }

  def getReadableAndOwners(dsId: String): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      val domId = request.identity.get.domId.get
      resourceAccFetcher
        .getOwnersAndReadersProfileOfResource(domId, dsId, TagRecordType.DATA_SET, userAPI = request.identity)
        .map(it => Json.toJson(it))
        .map(SuccessResponse(_))
    }

  def getDsUpdateStatus: Action[AnyContent] = SecuredActionAsync(DatasetResource, ManagePrivilege) {
    implicit request => implicit traceData: TraceData =>
      dataSourceUpdate.getDsUpdateManagerStatus.map(SuccessResponse(_))
  }

  def getUpdatableTableListForExcelPlugin(nameLike: Option[String], displayType: Option[String]): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, UpdatePrivilege) { implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val isAdmin = user.isAdmin
      datasourceMetaInfoManager
        .getUpdatableDataSetsForExcelPlugin(user, nameLike, displayType)
        .map(SuccessResponse(_))
    }

  def getSupportedDisplayTypeForExcelPlugin: Action[AnyContent] = Action { implicit request =>
    val titles = DisplayType.textMapping
    val supported = DisplayType.supportedByExcelPlugin
    val dataSets = supported.map(a =>
      Json.obj(
        "text" -> titles(a),
        "value" -> a
      )
    )
    SuccessResponse(dataSets)
  }

  def dataSetting(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSettingQuery](DatasetResource, UpdatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val datasourceConfig = request.body

        dataSources.taggedTraceDataForUserOperationWithoutName(
          user.domainId,
          dsId,
          AuditOpTypes.DsEditDataSet,
          Some(Json.toJson(request.body).toString)
        )

        datasourceUpdateSetting
          .updateSetting(dsId, user.domainId, Some(user), datasourceConfig)
          .map(SuccessResponse(_))
          .recover { case abe: AbstractBusinessException =>
            ErrorResponse(abe.code, traceData.getI18NMessage(abe.messageKey), abe.notifyType)
          }
    }

  def dataSettingForETLDataSet(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSettingForETLDataSet](DatasetResource, UpdatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = request.identity.get.domId.get
        dataSources.taggedTraceDataForUserOperationWithoutName(
          domId,
          dsId,
          AuditOpTypes.DsEditDataSet,
          Some(Json.toJson(request.body).toString)
        )
        for {
          canSetting <-
            if (user.isAdmin)
              Future.successful(true)
            else
              resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET)
          res <-
            if (canSetting) {
              datasourceMetaInfoManager.getConfig(domId, dsId).flatMap {
                case Some(dsConfig) =>
                  val dataSourceUpdateHooks = request.body.dataSourceUpdateHooks
                  val dataSourceUpdateHooksArray = Json.toJson(dataSourceUpdateHooks)
                  datasourceMetaInfoManager
                    .updateConfigByKey(domId, dsId, DATASOURCE_UPDATE_HOOK, Some(dataSourceUpdateHooksArray))
                    .map { _ =>
                      SuccessResponse("OK")
                    }
                case _ => errFuture(ErrorResponse.MISSING_FIELD, "CONFIG_FIELD_MISSING")()
              }
            } else {
              errFuture(ErrorResponse.PERMISSION_DENIED, "PERMISSION_DENIED.permissionDenied")()
            }
        } yield res
    }

  def updateDataSourceInfo(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSourceInfo](DatasetResource, UpdatePrivilege) {
      implicit request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domainId
        val req = request.body
        val isAdmin = request.logonUser.isAdmin
        (for {
          isOwner <- resourceAccChecker.canUseNonDirResource(user, dsId, TagRecordType.DATA_SET)
          res <-
            if (isOwner || isAdmin) {
              datasourceMetaInfoManager
                .updateDataSourceInfo(domId, dsId, req.description)
                .map {
                  case Right(num) =>
                    SuccessResponse(req.description)
                  case Left(msg) =>
                    ErrorResponse(ErrorResponse.UPDATE_ERROR, traceData.getI18NMessage(msg))
                }
                .recover { case exception: Exception =>
                  ErrorResponse(ErrorResponse.UPDATE_ERROR, traceData.getI18NMessage(exception.getMessage))
                }
            } else
              errorResFuture(PermissionDeniedException())
        } yield res).recover { case ex: java.util.NoSuchElementException =>
          logger.error(ex.getStackTrace.mkString("\n"))
          errorResponse(NotFoundException(traceData.getI18NMessage("NOT_FOUND.datasetNotFound")))
        }
    }

  def dataSettingForZhaoHang(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSettingQueryForZhaoHang](DatasetResource, UpdatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = request.identity.get.domId.get

        dataSources.taggedTraceDataForUserOperationWithoutName(
          domId,
          dsId,
          AuditOpTypes.DsEditDataSet,
          Some(Json.toJson(request.body).toString)
        )
        for {
          canSetting <-
            if (user.isAdmin)
              Future.successful(true)
            else
              resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET)
          res <-
            if (canSetting) {
              mergeAndUpdateDsSettingForZH(domId, dsId, request.body).flatMap(Future.successful).map { msg =>
                SuccessResponse(msg)
              }
            } else {
              errFuture(ErrorResponse.PERMISSION_DENIED, "PERMISSION_DENIED.permissionDenied")()
            }
        } yield res
    }

  private def mergeAndUpdateDsSettingForZH(
      domId: String,
      dsId: String,
      query: DataSettingQueryForZhaoHang
  )(implicit traceData: TraceData): Future[String] = {
    datasourceMetaInfoManager.getByDsId(dsId).flatMap {
      case Some(dsApi) =>
        val config = dsApi.config.getOrElse(JsObject.empty)
        val sourceType = (config \ "sourceType").asOpt[DataSourceOriginSourceType]
        sourceType match {
          case Some(DataSourceOriginSourceType.GUAN_INDEX) =>
            for {
              preCleanUpdateRes <-
                if (query.guanIndexIncrementalUpdateSetting.isDefined) {
                  val mergedSetting = mergePreCleanSetting(
                    config,
                    Json.toJson(query.guanIndexIncrementalUpdateSetting.get.preClean)
                  )
                  datasourceMetaInfoManager
                    .updateConfigByKey(
                      domId,
                      dsId,
                      GUANINDEX_UPDATE_SETTING,
                      Some(mergedSetting)
                    )
                    .map { result =>
                      if (result) "update preclean config success."
                      else "update preclean config failed."
                    }
                } else Future("preclean config not set.")
            } yield {
              preCleanUpdateRes
            }
          case _ =>
            for {
              needReflux2HiveUpdateRes <-
                if (query.needReflux2Hive.isDefined) {
                  datasourceMetaInfoManager
                    .updateConfigByKey(
                      domId,
                      dsId,
                      NEED_REFLUX_2_HIVE,
                      Some(Json.toJson(query.needReflux2Hive.get))
                    )
                    .map { result =>
                      if (result) {
                        dataSources.reflux2Hive4ZhaoHangIfNeeded(domId, dsId).map(_ => "update reflux config success.")
                      } else Future("update reflux config failed.")
                    }
                    .flatMap(result => result)
                } else Future("reflux config not set.")
            } yield {
              needReflux2HiveUpdateRes
            }
        }
      case _ =>
        Future(traceData.getI18NMessage("NOT_FOUND.datasetNotFound"))
    }
  }

  private def mergePreCleanSetting(dsConfig: JsValue, newValue: JsValue): JsValue = {
    val defaultObj = GuanIndexIncrementalUpdateSetting(enabled = true, "")
    val incrementalUpdateSettingNode =
      (dsConfig \ GUANINDEX_UPDATE_SETTING).asOpt[JsObject].getOrElse(Json.toJson(defaultObj).as[JsObject])
    incrementalUpdateSettingNode + (PRE_CLEAN, newValue)
  }

  /**
   * 对比两dataset，并根据 name／alias 默认关联。
   *
   * @return
   */
  def compareColumns(origDsId: String, destDsId: String): Action[AnyContent] =
    SecuredActionAsync(BaseResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      val domId = request.identity.get.domId.get
      (for {
        origDS <- datasourceMetaInfoManager.get(domId, origDsId)
        if origDS.nonEmpty
        destDS <- datasourceMetaInfoManager.get(domId, destDsId)
        if destDS.nonEmpty
        origFields: Seq[FieldAPI] <- fields.getByDsIdIncludeAggregation(origDsId)
        destFields <- fields.getByDsIdIncludeAggregation(destDsId)
      } yield {
        val destFieldsMap = destFields.flatMap { item =>
          if (item.alias.nonEmpty && item.alias.get.nonEmpty)
            Seq((item.alias.get.trim, item), (item.name.get.trim, item))
          else
            Seq((item.name.get.trim, item))
        }.toMap
        val allResWithDestFields = origFields.map { item =>
          val destFieldByName = destFieldsMap.get(item.name.get.trim)
          val destFieldByAlias = item.alias.flatMap {
            case alias if alias.nonEmpty =>
              destFieldsMap.get(alias.trim)
            case _ =>
              None
          }
          if (destFieldByName.exists(_.isAggregated.getOrElse(false) == item.isAggregated.getOrElse(false)))
            Map("origFields" -> item, "destFields" -> destFieldByName.get)
          else if (destFieldByAlias.exists(_.isAggregated.getOrElse(false) == item.isAggregated.getOrElse(false)))
            Map("origFields" -> item, "destFields" -> destFieldByAlias.get)
          else Map("origFields" -> item)
        }
        val result = Json.obj(
          "data" -> Json.obj("new_ds_fields" -> destFields, "columns" -> allResWithDestFields)
        )
        SuccessResponse(result)
      }).recover { case e: Throwable =>
        e.printStackTrace()
        SuccessResponse(Json.obj("data" -> JsNull))
      }
    }

  /**
   * dataset切换，指定的card的dataset也相应做切换
   *
   * @return
   */
  def changeDataset: Action[JsValue] = SecuredPostActionAsync[FieldAssocAPI](BaseResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      val domId = request.identity.get.domId.get
      val cdIds: Seq[String] = request.body.cdIds.getOrElse(Seq.empty[String])
      val fieldAssocAPI = request.body
      val resFuture = cards.getActualCdIdsOfChangeDataSet(domId, cdIds, fieldAssocAPI.origDsId.get).flatMap { seq =>
        cardManipulate.batchChangeDataSet4Cards(request.identity.get, fieldAssocAPI, seq)
      }
      resFuture
        .map { res =>
          val errMses = res.collect { case Left(msg) => msg }
          dataSources.taggedTraceDataForUserOperationWithoutName(
            domId,
            fieldAssocAPI.origDsId.get,
            AuditOpTypes.DsChangeDataSet,
            Some(Json.toJson(fieldAssocAPI).toString)
          )
          if (errMses.nonEmpty) {
            ErrorResponse(
              ErrorResponse.MULTIPLE_ERROR,
              s" ${errMses.size} 张卡片切换数据集失败： ${errMses.mkString(",")}"
            )
          } else SuccessResponse(Json.obj("status" -> "success"))
        }
  }

  def compareFieldsWithNewQuery(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[CompareFieldAPI](BaseResource, ReadPrivilege) {
      implicit request => implicit traceData: TraceData =>
        val domId = request.identity.get.domId.get
        val columns = request.body.columns
        val columnsWithIndex = columns.zipWithIndex.map { case (colProps, index) =>
          FieldAPI(name = Option(colProps.name), fdType = colProps.fdType, seqNo = Option(index))
        }

        dataSources.taggedTraceDataForUserOperationWithoutName(
          domId,
          dsId,
          AuditOpTypes.DsEditDataSet,
          Some(Json.toJson(request.body).toString)
        )
        datasourceMetaInfoManager.getConfig(domId, dsId).flatMap { dsConfig =>
          val primaryKeyColumns =
            (Json.parse(dsConfig.get) \ "primaryKeyColumns").asOpt[Seq[String]].getOrElse(Seq.empty)
          fields.getByDsIdExcludeAggregation(dsId).flatMap { origFields: Seq[FieldAPI] =>
            val fieldsMapping = schemaManager
              .getFieldsMapping(origFields, columnsWithIndex)
              .map(
                _.toList
                  .map { tup =>
                    if (tup._1 == "origField") {
                      val isPrimaryKey = primaryKeyColumns.exists(pk => tup._2.name.contains(pk))
                      (
                        tup._1,
                        Json.obj(
                          "name" -> tup._2.alias.orElse(tup._2.name),
                          "fdType" -> tup._2.fdType,
                          "fdId" -> tup._2.fdId,
                          "isPrimaryKey" -> isPrimaryKey
                        )
                      )
                    } else {
                      (tup._1, Json.obj("name" -> tup._2.alias.orElse(tup._2.name), "fdType" -> tup._2.fdType))
                    }
                  }
                  .toMap
              )
            val result = Json.obj("fieldsMapping" -> fieldsMapping, "newFields" -> columnsWithIndex)
            Future.successful(SuccessResponse(result))
          }
        }
    }

  def guanFormChangeAccount(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[ChangeAccountAPI](BaseResource, ReadPrivilege) {
      implicit request => implicit traceData: TraceData =>
        val acId = request.body.acId
        val domId = request.logonUser.domId.get
        datasourceMetaInfoManager.changeDsAccountIdByDsId(domId, dsId, acId)
        Future.successful(SuccessResponse("account changed"))
    }

  def changeQuery(dsId: String): Action[JsValue] = SecuredPostActionAsync[ChangeQueryAPI](BaseResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val changeQueryAPI = request.body

      dataSources.changeQueryModel(dsId, user, changeQueryAPI).map { _ =>
        SuccessResponse("model changed")
      }
  }

  def refreshWithToken(dsId: String, token: String): Action[AnyContent] = UnsecuredActionAsync {
    clusteringService.forwardToMaster { request => implicit traceData: TraceData =>
      traceData.logger.info(s"[DATASOURCE_UPDATE_FOR_TOKEN](dsId: $dsId, token: $token)")
      datasourceUpdateTrigger
        .triggerDataSourceUpdateWithRetry(dsId, token = Some(token))
        .map(SuccessResponse(_))
        .recover { case exp: DatasourceUpdateException =>
          ErrorResponse(
            exp.code,
            traceData.getI18NMessage(exp.messageKey),
            exp.notifyType
          )
        }
    }
  }

  def getDataFetchToken(dsId: String, action: Option[String] = None): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ManagePrivilege) { request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get

      datasourceMetaInfoManager.get(user.domId.get, dsId).flatMap { dsOpt =>
        val existedToken = dsOpt.flatMap { ds =>
          ds.config.flatMap { config =>
            (config \ Constants.DATA_FETCH_TOKEN).asOpt[String]
          }
        }
        existedToken match {
          case Some(token) =>
            action match {
              case Some(act) if act.equalsIgnoreCase("reset") =>
                val newToken = RandUtil.uuid
                datasourceMetaInfoManager
                  .updateConfigByKey(
                    domId,
                    dsId,
                    Constants.DATA_FETCH_TOKEN,
                    Option(JsString(newToken))
                  )
                  .map { _ =>
                    SuccessResponse(Json.obj(Constants.DATA_FETCH_TOKEN -> newToken))
                  }
              case Some(act) if act.equalsIgnoreCase("disable") =>
                datasourceMetaInfoManager
                  .updateConfigByKey(user.domId.get, dsId, Constants.DATA_FETCH_TOKEN, None)
                  .map { _ =>
                    SuccessResponse("success")
                  }
              case _ =>
                Future.successful(SuccessResponse(Json.obj(Constants.DATA_FETCH_TOKEN -> token)))
            }
          case _ =>
            action match {
              case Some(act) if act.equalsIgnoreCase("disable") =>
                Future.successful(SuccessResponse("success"))
              case _ =>
                val token = RandUtil.uuid
                datasourceMetaInfoManager
                  .updateConfigByKey(
                    domId,
                    dsId,
                    Constants.DATA_FETCH_TOKEN,
                    Option(JsString(token))
                  )
                  .map(_ => SuccessResponse(Json.obj(Constants.DATA_FETCH_TOKEN -> token)))
            }
        }
      }
    }

  def getDataWithToken(dsId: String, token: String, offset: Int, limit: Int): Action[JsValue] =
    UnsecuredPostActionAsync[DataSourceDataQuery] { request => implicit traceData: TraceData =>
      val query = request.body
      val operator = request.identity
      datasourceMetaInfoManager.getByDsId(dsId).flatMap {
        case Some(ds) =>
          val authorized = ds.config.exists { x => (x \ Constants.DATA_FETCH_TOKEN).asOpt[String].contains(token) }
          if (authorized) {
            datasourceMetaInfoManager.getCols(dsId).flatMap { fieldSeq =>
              val selectedCols = query.cols match {
                case Some(colNames) =>
                  fieldSeq.filter(fd => colNames.contains(fd.alias.orElse(fd.name).get))
                case _ =>
                  fieldSeq
              }
              val filters = query.filters.map { filterList =>
                filterList.map { filter =>
                  val filterId = fieldSeq.find(_.name.equals(filter.name)).flatMap(_.fdId)
                  filter.copy(fdId = filterId)
                }
              }
              val dsFieldInfo = DsFieldInfo.buildDsFieldInfo(fieldSeq, ds)
              dataSources
                .preview(
                  ds.domId.get,
                  dsFieldInfo,
                  Map.empty[String, SecurityFilterContext],
                  None,
                  limit,
                  offset,
                  filters,
                  operator = operator,
                  columns = Some(selectedCols)
                )
                .flatMap { res =>
                  dataSources
                    .getCountWithFilter(
                      ds.domId.get,
                      dsFieldInfo,
                      Map.empty[String, SecurityFilterContext],
                      filters
                    )
                    .map { total =>
                      SuccessResponse(
                        Json.obj(
                          "columns" -> selectedCols.map(_.name),
                          "total" -> total,
                          "count" -> res.getOrElse(Seq()).size,
                          "data" -> res
                        )
                      )
                    }
                }
            }
          } else {
            Future.successful(notFound("NOT_FOUND.dataSourceNotFound"))
          }
        case _ =>
          Future.successful(notFound("NOT_FOUND.dataSourceNotFound"))
      }
    }

  /**
   * sapbw类型的数据集，编辑prompts并保存。 其他类型的数据集，暂不支持这个功能
   *
   * @param dsId
   * @return
   */
  def editQueryPrompts(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[TableQueryPreviewQuery](DatasetResource, UpdatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = request.identity.get.domId.get
        val tableQuery = request.body.tableQuery.get

        // 是否有编辑权限
        val canEditFuture = resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET)
        canEditFuture.flatMap { canAccess =>
          if (canAccess) {
            datasourceMetaInfoManager.get(domId, dsId).flatMap {
              case Some(dataSource) =>
                // 获取数据账户
                accounts.adminGetDetailedAccount(domId, dataSource.acId.getOrElse("")).flatMap {
                  case Some(account) =>
                    // 对于sapbw类型的数据集，处理用户输入的prompts，重新生成mdx
                    val newTableQuery = OlapService.processQueryIfNecessary(account, tableQuery)

                    // 保存新的query信息
                    datasourceMetaInfoManager
                      .updateConfigByKey(
                        domId,
                        dsId,
                        "tableQuery",
                        Some(Json.toJson(newTableQuery))
                      )
                      .flatMap { updated =>
                        // query信息更新成功后，更新数据集
                        if (updated) {
                          dataSourceUpdate.triggerUpdate(domId, dsId).map(_.toResult)
                        } else {
                          errFuture(ErrorResponse.SERVER_ERROR, "DATA_SOURCE.updateFailed")()
                        }
                      }

                  case _ =>
                    errFuture(ErrorResponse.NOT_FOUND, "NOT_FOUND.accountNotFound")(NotifyType.VALIDATE)
                }

              case _ =>
                errFuture(ErrorResponse.NOT_FOUND, "NOT_FOUND.dataSourceNotFound")(NotifyType.VALIDATE)
            }
          } else {
            Future.successful(errorResponse(PermissionDeniedException()))
          }
        }
    }

  /**
   * sap bw类型的数据集，在"数据模型"中获取prompts信息，调用此接口； 其他类型的数据集，暂不支持这个功能
   *
   * @param dsId
   * @return
   */
  def getQueryPrompts(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get

      /**
       * 检查权限
       */
      val canAccessFuture =
        if (user.isAdmin)
          Future.successful(true)
        else {
          for {
            isOwner <- resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET)
            readable <-
              if (isOwner) successful(true)
              else resourceAccChecker.canUseNonDirResource(user, dsId, TagRecordType.DATA_SET)
          } yield readable || isOwner
        }

      canAccessFuture.flatMap { canAccess =>
        if (canAccess) {
          datasourceMetaInfoManager.get(domId, dsId).flatMap {
            case Some(dataSource) =>
              // 获取数据账户
              accounts.adminGetDetailedAccount(domId, dataSource.acId.getOrElse("")).flatMap {
                case Some(account) =>
                  val tableQueryOpt = (dataSource.config.getOrElse(JsObject.empty) \ "tableQuery")
                    .asOpt[TableQueryDefinition]
                  // 获取cube name
                  val tableName = tableQueryOpt.flatMap(_.table)
                  // 上次选择的prompts信息
                  val lastVariables = tableQueryOpt.flatMap(_.prompts.map(_.as[Seq[SapVariable]]))

                  // 只有sapbw类型的账户才支持prompts，此时，数据集中的config中需要包含目标cube name
                  if (account.cnId.getOrElse("") == "sapbw" && tableName.isDefined) {
                    Future {
                      // 查询这个cube上的variables
                      val mergeVariables = OlapService
                        .getSapVariables(account, tableName.get)
                        .map { variables =>
                          variables.map { variable =>
                            // 查询上次选择的variables信息，对于和当前的variables匹配的（如果cube的variables没有被编辑过，那么是完全匹配的）,
                            // 取出其选择的值selections,和当前的variable合并
                            val matchedVariable = lastVariables.getOrElse(Seq.empty).find(_.name == variable.name)
                            if (matchedVariable.isDefined)
                              variable.copy(selections = matchedVariable.get.selections)
                            else variable
                          }
                        }
                        .getOrElse(Seq.empty)

                      SuccessResponse(mergeVariables)
                    }.recover { case e: Exception =>
                      traceData.logger.error("unexpected error happened when get query prompts,", e)
                      ErrorResponse(ErrorResponse.OLAP_ERROR, e.toString)
                    }
                  } else
                    errFuture(INVALID_DATA_SOURCE, "INVALID_DATA_SOURCE.promptsNotSupported")(NotifyType.VALIDATE)
                case _ =>
                  errFuture(ErrorResponse.NOT_FOUND, "NOT_FOUND.accountNotFound")(NotifyType.VALIDATE)
              }
            case _ => errFuture(ErrorResponse.NOT_FOUND, "NOT_FOUND.dataSourceNotFound")(NotifyType.VALIDATE)
          }
        } else errFuture(ErrorResponse.PERMISSION_DENIED, "PERMISSION_DENIED.permissionDenied")()
      }
  }

  def clearData(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSourceRowFilter](DatasetResource, UpdatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domId.get
        val clearQuery = request.body
        doClearOrPreview(domId, dsId, user, clearQuery, isClear = true)
    }

  def previewDataOnClear(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSourceRowFilter](DatasetResource, UpdatePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domId.get
        val clearQuery = request.body
        doClearOrPreview(domId, dsId, user, clearQuery)
    }

  def previewForPreClean(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSourceRule](DatasetResource, ReadPrivilege) { request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      val dsRule = request.body
      val dsId = dsRule.dsId.get
      val rule = dsRule.rule.get
      dpAdapter.resolve(domId, rule, rule, None).flatMap { rule =>
        datasourceMetaInfoManager.getWithCols(domId, dsId, true).flatMap {
          case Some(dsAPI) =>
            dataSources.previewBySQL(domId, dsAPI, rule).map(SuccessResponse(_))
          case _ =>
            errFuture(ErrorResponse.NOT_FOUND, "NOT_FOUND.dataSourceNotFound")(NotifyType.VALIDATE)
        }
      }
    }

  def cleanByCondition(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[DataSourceRule](DatasetResource, DeletePrivilege) {
      request => implicit traceData: TraceData =>
        val user = request.identity.get
        val domId = user.domId.get
        val dsRule = request.body
        val dsId = dsRule.dsId.get
        val rule = dsRule.rule.get
        dpAdapter.resolve(domId, rule, rule, None).flatMap { rule =>
          canDataSourceBeClear(domId, dsId).flatMap {
            case true =>
              datasourceMetaInfoManager.getWithCols(domId, dsId, true).flatMap {
                case Some(dsAPI) =>
                  isDataSourceProcessing(domId, dsId).flatMap {
                    case true =>
                      errFuture(ErrorResponse.SERVER_ERROR, "SERVER_ERROR.clearDataSetFailed")()
                    case false =>
                      storageManager.clearBySQL(domId, user, dsId, dsAPI, rule).map(SuccessResponse(_))
                  }
                case _ =>
                  errFuture(ErrorResponse.NOT_FOUND, "NOT_FOUND.dataSourceNotFound")(NotifyType.VALIDATE)
              }
            case false => errFuture(ErrorResponse.SERVER_ERROR, "SERVER_ERROR.dataSourceTypeClearFailed")()
          }
        }
    }

  private def doClearOrPreview(
      domId: String,
      dsId: String,
      user: UserAPI,
      rowFilter: DataSourceRowFilter,
      isClear: Boolean = false
  )(implicit traceData: TraceData) = {
    canDataSourceBeClear(domId, dsId).flatMap {
      case true =>
        resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET).flatMap {
          case true =>
            datasourceMetaInfoManager.getWithCols(domId, dsId, true).flatMap {
              case Some(dsAPI) =>
                if (isClear) {
                  isDataSourceProcessing(domId, dsId).flatMap {
                    case true =>
                      errFuture(ErrorResponse.SERVER_ERROR, "SERVER_ERROR.clearDataSetFailed")()
                    case false =>
                      storageManager.clearData(user, dsAPI, rowFilter).map { response =>
                        dataSources
                          .taggedTraceDataForUserOperationWithoutName(
                            domId,
                            dsId,
                            AuditOpTypes.DsClearDataSet,
                            Some(Json.toJson(rowFilter).toString)
                          )
                        SuccessResponse(response)
                      }
                  }
                } else {
                  dataSources.previewOnClearData(domId, user, dsAPI, rowFilter).map(SuccessResponse(_))
                }
              case _ =>
                errFuture(ErrorResponse.NOT_FOUND, "NOT_FOUND.dataSourceNotFound")(NotifyType.VALIDATE)
            }
          case false =>
            errFuture(ErrorResponse.PERMISSION_DENIED, "PERMISSION_DENIED.permissionDenied")()
        }
      case false =>
        errFuture(ErrorResponse.SERVER_ERROR, "SERVER_ERROR.dataSourceTypeClearFailed")()
    }
  }

  private def canDataSourceBeClear(domId: String, dsId: String) = {
    datasourceMetaInfoManager.getSourceTypeAndDisplayType(domId, dsId).map {
      case Some(sourceTypeAndDisplayType) =>
        val sourceTypeOpt = sourceTypeAndDisplayType._1
        val displayType = sourceTypeAndDisplayType._2
        sourceTypeOpt.isDefined && DataSourceOriginSourceType.supportingClearingData.contains(sourceTypeOpt.get) ||
        DisplayType.fileUploadTypes.contains(displayType)

      case _ =>
        false
    }
  }

  private def canDataSourceChangePrimaryKeys(domId: String, dsId: String) = {
    datasourceMetaInfoManager.getSourceTypeAndDisplayType(domId, dsId).map {
      case Some(sourceTypeAndDisplayType) =>
        val sourceTypeOpt = sourceTypeAndDisplayType._1
        sourceTypeOpt.isDefined && sourceTypeOpt.get == DataSourceOriginSourceType.GUAN_INDEX

      case _ =>
        false
    }
  }

  def universeTableList(acId: String, nameLike: Option[String]): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      accounts.canUse(user, acId).flatMap { canUse =>
        if (canUse) {
          accounts.adminGetDetailedAccount(domId, acId).flatMap { accountOpt =>
            if (accountOpt.isDefined) {
              val authConfig = accountOpt.get.authConfig
              universeTableService.getUniverseTableList(domId, nameLike, authConfig).map { results =>
                if (results._1) {
                  SuccessResponse(results._2.getOrElse(JsArray.empty))
                } else {
                  ErrorResponse(
                    FETCH_DATA_ERROR,
                    results._2.getOrElse(Json.obj()).toString(),
                    NotifyType.VALIDATE
                  )
                }
              }
            } else {
              Future.successful(ErrorResponse(FETCH_DATA_ERROR, Json.obj().toString(), NotifyType.VALIDATE))
            }
          }
        } else errorResFuture(PermissionDeniedException())
      }
    }

  def universeTableAndDirList(acId: String, dirId: Option[String], nameLike: Option[String]): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      accounts.canUse(user, acId).flatMap { canUse =>
        if (canUse) {
          accounts.adminGetDetailedAccount(domId, acId).flatMap { accountOpt =>
            if (accountOpt.isDefined) {
              val authConfig = accountOpt.get.authConfig
              universeTableService.getUniverseTableAndDirList(domId, nameLike, dirId, authConfig).map { results =>
                if (results._1) {
                  SuccessResponse(results._2.getOrElse(JsObject.empty))
                } else {
                  ErrorResponse(
                    FETCH_DATA_ERROR,
                    results._2.getOrElse(Json.obj()).toString(),
                    NotifyType.VALIDATE
                  )
                }
              }
            } else {
              Future.successful(ErrorResponse(FETCH_DATA_ERROR, Json.obj().toString(), NotifyType.VALIDATE))
            }
          }
        } else errorResFuture(PermissionDeniedException())
      }
    }

  def universeTableColumns(acId: String, tableId: String): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { request => implicit traceData: TraceData =>
      val domId = request.identity.get.domId.get
      accounts.adminGetDetailedAccount(domId, acId).flatMap {
        case Some(account) =>
          universeTableService.getUniverseTableInfo(domId, tableId, account.authConfig).map {
            case Right(tableInfo) =>
              val newFields = universeTableService.convertToFieldSeq(tableInfo.fields.getOrElse(Seq.empty))
              SuccessResponse(newFields)
            case Left(errMsg) =>
              ErrorResponse(FETCH_DATA_ERROR, errMsg, NotifyType.VALIDATE)
          }
        case _ =>
          Future.successful(
            ErrorResponse(FETCH_DATA_ERROR, "failed to fetch column info", NotifyType.VALIDATE)
          )
      }
    }

  def universeChangeTableId: Action[JsValue] =
    SecuredPostActionAsync[UniverseDsRefresh](DatasetResource, UpdatePrivilege) {
      request => implicit traceData: TraceData =>
        val universeDsRefresh = request.body
        val domId = universeDsRefresh.domId
        val dsId = universeDsRefresh.dsId
        val tableQueryDefinition = TableQueryDefinition(
          queryType = "query",
          query = Some(universeDsRefresh.tableId)
        )
        datasourceMetaInfoManager
          .updateConfigByKey(domId, dsId, "tableQuery", Some(Json.toJson(tableQueryDefinition)))
          .map { _ =>
            SuccessResponse("Id changed")
          }

    }

  def universeRegister(): Action[JsValue] = SecuredPostActionAsync[JsObject](DatasetResource, CreatePrivilege) {
    request => implicit traceData: TraceData =>
      val user = request.identity.get
      val params = request.body
      val paramName1 = "projectId"
      val paramName2 = "datasetId"
      val paramName3 = "datasetName"
      val domId = (params \ paramName1).asOpt[String]
      val dsId = (params \ paramName2).asOpt[String]
      val dsName = (params \ paramName3).asOpt[String]
      if (domId.isEmpty) {
        Future.successful(
          ErrorResponse(
            ErrorResponse.MISSING_PARAM,
            s"MISSING_PARAM.$paramName1"
          )
        )
      } else if (dsId.isEmpty || dsName.isEmpty) {
        Future.successful(
          ErrorResponse(
            ErrorResponse.MISSING_PARAM,
            s"MISSING_PARAM.$paramName2"
          )
        )
      } else {
        dataSources.registerUniverseDataset(domId.get, dsId.get, dsName.get, user).map { res =>
          if (res.success) SuccessResponse("Success") else res.toResult
        }
      }
  }

  def universeRefreshTable: Action[JsValue] = UnsecuredPostActionAsync[UniverseDsRefresh] {
    request => implicit traceData: TraceData =>
      val universeDsRefresh = request.body
      val domId = universeDsRefresh.domId
      val dsId = universeDsRefresh.dsId
      val loginUser = request.identity
      datasourceMetaInfoManager.get(domId, dsId).flatMap { dsOpt =>
        if (dsOpt.isEmpty) {
          Future.successful(
            ErrorResponse(
              ErrorResponse.FETCH_DATA_ERROR,
              traceData.getI18NMessage("NOT_FOUND.dataSourceNotFound"),
              NotifyType.VALIDATE
            )
          )
        } else {
          if (dsOpt.get.displayType != DisplayType.UNIVERSE) {
            Future.successful(
              ErrorResponse(
                ErrorResponse.FETCH_DATA_ERROR,
                traceData.getI18NMessage("INVALID_PARAMETERS.notUniverseDisplayType"),
                NotifyType.VALIDATE
              )
            )
          } else {
            dataSources.refreshUniverseTable(loginUser, universeDsRefresh).map {
              case Right(_) => SuccessResponse("model changed!")
              case Left(errMsg) => ErrorResponse(ErrorResponse.FETCH_DATA_ERROR, errMsg, NotifyType.VALIDATE)
            }
          }
        }
      }
  }

  def deltaMigrate(): Action[AnyContent] = UnsecuredActionAsync { request => implicit traceData: TraceData =>
    dataSources.migrateToDelta.flatMap { _ =>
      Future.successful(SuccessResponse("migrate end"))
    }
  }

  // Why POST ?
  def getColumns(dsId: String): Action[JsValue] = SecuredPostActionAsync[JsObject](DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      datasourceMetaInfoManager.getCols(dsId).map(SuccessResponse(_))
  }

  def getSchema(dsId: String): Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      datasourceMetaInfoManager.getCols(dsId).map(SuccessResponse(_))
  }

  def listDataSets: Action[JsValue] = SecuredPostActionAsync[JsObject](DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      val dTypeOpt = (request.body \ "displayType").asOpt[String]
      val displayType = dTypeOpt.map(DisplayType.withName).map(_.id)
      datasourceMetaInfoManager.getByDomainDsType(domId, displayType).map { res =>
        val response = res.map(_.copy(storageId = None, version = None, config = None))
        SuccessResponse(Json.obj("datasets" -> response))
      }
  }

  def updateDataSetStructure(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[JsObject](BaseResource, UpdatePrivilege) {
      implicit request => implicit traceData: TraceData =>
        val user = request.identity.get
        val updateReqsOpt = (request.body \ "columns").asOpt[Seq[UpdateColNameTypeReq]].map(_.map(_.trimName))
        val canEditFur =
          if (user.isAdmin) Future.successful(true)
          else
            resourceAccChecker.canManageNonDirResource(user, dsId, TagRecordType.DATA_SET)
        canEditFur.flatMap {
          case true =>
            if (updateReqsOpt.isDefined) {
              schemaManager
                .updateStructure(
                  dsId,
                  user,
                  updateReqsOpt.get,
                  Some(request.body)
                )
                .map { r =>
                  val errMsgs = r._2.collect { case Left(msg) => msg }
                  if (errMsgs.nonEmpty) {
                    ErrorResponse(
                      ErrorResponse.MULTIPLE_ERROR,
                      s"Partial cards Update DataSet fail ${errMsgs.mkString("\n")}"
                    )
                  } else SuccessResponse(r._1)
                }
            } else Future.successful(SuccessResponse("No columns change"))
          case _ =>
            throw new RuntimeException("permissionDenied")
        }
    }

  def checkForUpdateStructure(dsId: String): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      for {
        usedByCard <- cards.getCardsByDsId(dsId, user, pages).map(_._1.nonEmpty)
        usedByETL <- smartETLQueryService.getByInputDsId(domId, dsId).map(_.nonEmpty)
        security <- dataSecurityManager.getSecurityFilter(domId, dsId).map { x => x.column.enabled || x.row.enabled }
        usedByRealTime <- rtDsService.getDataSourcesByLookupDsId(dsId).map(_.nonEmpty)
        usedByView <- dataSources.getChildDsWithReadableFlag(domId, dsId, user, DisplayType.SPARK_VIEW).map(_.nonEmpty)
      } yield SuccessResponse(
        Json.obj(
          "etl" -> usedByETL,
          "security" -> security,
          "view" -> usedByView,
          "realtime" -> usedByRealTime,
          "card" -> usedByCard
        )
      )
    }

  def refreshWithFile(dsId: String, overwrite: Boolean, fileType: Option[String]): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      dataSources.getDsApiForRefreshWithFile(dsId, user).flatMap {
        case Left(result) => Future.successful(result)
        case Right(dsAPI) =>
          isDataSourceProcessing(dsAPI.domId.get, dsId).flatMap {
            case true => errFuture(ErrorResponse.SERVER_ERROR, "SERVER_ERROR.updateDataSetFailed")()
            case false => guanIndexUpdateManager.refreshGuanIndexDsWithFile(dsAPI, overwrite, fileType)
          }
      }
    }

  def markSensitiveDataSet(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[JsObject](DatasetResource, UpdatePrivilege) {
      implicit request => implicit traceData: TraceData =>
        val sensitive = (request.body \ Constants.SENSITIVE).asOpt[Boolean].getOrElse(false)
        val allowBusinessDirectAccess =
          (request.body \ Constants.ALLOW_BUSINESS_DIRECT_ACCESS).asOpt[Boolean].getOrElse(false)
        val keys = Seq(Constants.SENSITIVE, Constants.AUDIT_TIME, Constants.ALLOW_BUSINESS_DIRECT_ACCESS)
        val values = Seq(
          JsBoolean(sensitive),
          JsString(new Timestamp(System.currentTimeMillis()).toString),
          JsBoolean(allowBusinessDirectAccess)
        )
        datasourceMetaInfoManager
          .updateConfigByKeyValue(request.domainId, dsId, keys, values)
          .map(_ => SuccessResponse("sucess"))
    }

  def updateFieldGroup(dsId: String): Action[JsValue] =
    SecuredPostActionAsync[JsObject](DatasetResource, UpdatePrivilege) { request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      val fieldGroup = (request.body \ "fdGroup").asOpt[JsArray]
      fieldGroup
        .map(x => datasourceMetaInfoManager.updateConfigByKeyValue(request.domainId, dsId, Seq("fdGroup"), Seq(x)))
        .getOrElse(Future.successful(0))
        .map(_ => SuccessResponse("sucess"))
    }

  def getFieldGroup(dsId: String): Action[AnyContent] = {
    SecuredActionAsync(DatasetResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      dataSources.getElemOfConfig(request.logonUser.domId.get, dsId, "fdGroup").map { resOpt =>
        SuccessResponse(resOpt.map(x => Json.obj("fdGroup" -> x)).getOrElse(Json.obj("fdGroup" -> JsArray())))
      }
    }
  }

  def getRowCount(dsId: String): Action[AnyContent] =
    SecuredActionAsync(DatasetResource, ReadPrivilege) { implicit request => implicit traceData: TraceData =>
      val user = request.identity.get
      val domId = user.domId.get
      dataSources.updateDsRowCount(domId, dsId).map { rowCount =>
        SuccessResponse(Json.obj("rowCount" -> rowCount))
      }
    }

  def doVacuum(domId: Option[String], dsId: Option[String]): Action[AnyContent] = {
    SecuredActionAsync(DatasetResource, UpdatePrivilege) { implicit request => implicit traceData: TraceData =>
      val vacuumOp = if (domId.nonEmpty && dsId.nonEmpty) {
        storageManager.doVacuumForDs(domId.get, dsId.get)
      } else {
        storageManager.doVacuum
      }
      vacuumOp.map { _ =>
        SuccessResponse("trigger success")
      }
    }
  }

  def downloadUpdateFieldAliasTemplate: Action[AnyContent] = SecuredActionAsync(DatasetResource, ReadPrivilege) {
    implicit request => implicit traceData: TraceData =>
      datasourceTemplateService.downloadUpdateFieldAliasTemplate.map { info =>
        IOFileHelpers.exportForDownloadFile(
          DownloadFileRequest(
            fileName = info.name,
            targetFile = new File(info.path),
            fileType = ContentTypeDefinition.SHEET_CONTENT_TYPE
          )
        )
      }
  }

  def importUpdateFieldAliasTemplate(dsId: String): Action[MultipartFormData[Files.TemporaryFile]] =
    SecuredUploadActionAsync(DatasetResource, ManagePrivilege) { implicit request => implicit traceData: TraceData =>
      val user = request.logonUser

      request.body.file("new-file") match {
        case Some(filePart) =>
          val tableFile = Table2dFile.convertFrom(filePart) { case (path, name) =>
            DefaultTable2dFile(path, name)
          }
          datasourceTemplateService
            .importUpdateFieldAliasTemplate(dsId, user, tableFile)
            .map(SuccessResponse(_))
        case _ =>
          Future.successful {
            ErrorResponse(
              ErrorResponse.FILE_CHECK_ERROR,
              "upload-file not exist"
            )
          }
      }
    }

  def doUpdateUBAR(date: Option[String]): Action[AnyContent] = {
    SecuredActionAsync(DatasetResource, UpdatePrivilege) { implicit request => implicit traceData: TraceData =>
      val domId = request.identity.flatMap(_.domId).get
      datasourceMetaInfoManager.get(domId, BuiltInSql.ubaDsId).flatMap {
        case Some(dataSourceAPI) =>
          guanIndexUpdateManager.incrementalUpdateUBAR(domId, dataSourceAPI, date).map { _ =>
            SuccessResponse("ok")
          }
        case _ => Future.successful(SuccessResponse("ok"))
      }
    }
  }
}
