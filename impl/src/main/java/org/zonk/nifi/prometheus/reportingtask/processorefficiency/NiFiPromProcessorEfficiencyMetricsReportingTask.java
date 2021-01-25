/*
 * NiFi reporting task to produce processor efficiency metrics using Apache commons'
 * math3::SimpleRegression (namely, slope and intercept).
 *
 * Report on running processors that match a provided type and name pattern expression,
 * and optionally within the confines of a specified ProcessGroup hierarchy.
 *
 * Format metrics in Prometheus' format/syntax and send to provided SSL endpoint.
 *
 *
 * TODO: write custom validators for configuration properties (it should be noted that the configuration properties MUST
 * be validated and verified at schedule/run time, because some configuration property values refer to elements that can
 * be modified outside of the management aspects of this ReportingTask.
 * 
 * This code is built against Java-11 using Maven-3.6.3
 */

package org.zonk.nifi.prometheus.reportingtask.processorefficiency;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;

import com.google.auto.service.AutoService;
import org.apache.commons.collections4.queue.CircularFifoQueue;
import org.apache.commons.math3.stat.regression.SimpleRegression;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.nifi.annotation.configuration.DefaultSchedule;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.lifecycle.OnShutdown;
import org.apache.nifi.annotation.lifecycle.OnStopped;
import org.apache.nifi.annotation.behavior.Restricted;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.controller.ConfigurationContext;
import org.apache.nifi.controller.status.ConnectionStatus;
import org.apache.nifi.controller.status.ProcessGroupStatus;
import org.apache.nifi.controller.status.ProcessorStatus;
import org.apache.nifi.controller.status.RunStatus;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.reporting.AbstractReportingTask;
import org.apache.nifi.reporting.ReportingContext;
import org.apache.nifi.reporting.ReportingTask;
import org.apache.nifi.scheduling.SchedulingStrategy;
import org.apache.nifi.security.util.KeyStoreUtils;
import org.apache.nifi.ssl.SSLContextService;

@Tags({"reporting", "processor metrics", "prometheus", "grafana"})
@Restricted // Writes to socket, and presume this needs to be tagged as restricted.
@CapabilityDescription("Report processor metrics to Prometheus' push_gateway et al." +
     " First and foremost, as processor names are reported as metric label values, the NiFi" +
     " data-flow administrator MUST acknowledge that processor names, as coupled to metric" +
     " flow values, are reported within privacy / sensitivity limits. What metrics to report is determined by" +
     " the processor type filter, the starting process group (default to 'root', as signifying entire canvas)," +
     " and the processor name regex filter. The process group hierarchy is traversed to locate processors" +
     " to report metrics. A property exists for the NiFi data-flow administrator to set the site moniker" +
     " (no default). The system moniker is determined by the root canvas (which is" +
     " also the window-title for the NiFi UI. The default scheduling period is 1 minute." +
     " Efficiency metrics are slope and intercept, computed using Apache commons / math3 SimpleRegression," +
     " based on schedule and number of samples (ReportingTask configuration properties)."
)
@DefaultSchedule(strategy = SchedulingStrategy.TIMER_DRIVEN, period = "60 sec")
@AutoService(ReportingTask.class)
public class NiFiPromProcessorEfficiencyMetricsReportingTask extends AbstractReportingTask
{

   /**
    * Implement Map.Entry such that time and metric value (both long types)
    * are converted to Double for use with Apache commons' math3::SimpleRegression.
    */
   static protected class TimeSeriesPair implements Map.Entry<Double, Double>
   {
      protected long time = 0L;
      protected long value = 0L;

      public TimeSeriesPair(long time, long value)
      {
         this.time = time;
         this.value = value;
      }

      @Override
      public Double getKey()
      {
         return Double.valueOf(time);
      }

      @Override
      public Double getValue()
      {
         return Double.valueOf(value);
      }

      @Override
      public Double setValue(Double arg)
      {
         if (arg != null) { value = arg.longValue(); }
         return Double.valueOf(value);
      }
   }

   // NiFi configuration properties (appears on the NiFi UI 'edit properties' for the reporting task)

   // Note that the SSL context service binds us to a particular version of Apache NiFi framework
   // (which is specified in the pom.xml -- for which we use a maven Profile).
   public static final PropertyDescriptor SSL_CONTEXT = new PropertyDescriptor.Builder()
        .name("SSL Context Service")
        .displayName("SSL Context Service")
        .description("The SSL Context Service provides SSL credentials for communicating with the prometheus' server")
        .required(false)
        .identifiesControllerService(SSLContextService.class)
        .build();

   public static final PropertyDescriptor PROM_ENDPOINT_URL = new PropertyDescriptor.Builder()
        .name("Metrcics endpoint URL")
        .description("Prometheus push_gateway/collector endpoint URL.")
        .required(true)
        .defaultValue("https://host:port/rest-path")
        .addValidator(StandardValidators.URL_VALIDATOR)
        .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
        .build();

   // There is no regex for this property (by design).
   public static final PropertyDescriptor PROCESSOR_TYPE_FILTER = new PropertyDescriptor.Builder()
        .name("Processor Type Filter")
        .description("A processor type must be specified explicitly, such as 'PostOrderup'.")
        .required(true)
        .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
        .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
        .build();

   // The processor name property encourages Java REGEX
   public static final PropertyDescriptor PROCESSOR_NAME_FILTER = new PropertyDescriptor.Builder()
        .name("Processor Name Filter")
        .description("Only processor names that match the given expression, along with processor type, will be used for reporting metrics.")
        .required(true)
        .defaultValue("[^\\.].*")
        .addValidator(StandardValidators.REGULAR_EXPRESSION_VALIDATOR)
        .build();

   // There is no regex for this property (by design).
   public static final PropertyDescriptor PROCESS_GROUP_FILTER = new PropertyDescriptor.Builder()
        .name("Process Group Filter")
        .description("Process group to start traversal." +
                     " Reminder that the nature of process group is that of a hierarchy (that is, group of groups, potentially)." +
                     " We default to all process groups using 'root'." +
                     " If there are multiple process groups with the same matching name, we only use the first match encountered.")
        .required(true)
        .defaultValue("root")
        .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
        .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
        .build();

   // site is a PIR convention
   public static final PropertyDescriptor PROCESSOR_SITE = new PropertyDescriptor.Builder()
        .name("Reporting site")
        .description("Site reported to Prometheus. Must be non-blank.")
        .required(true)
        .addValidator(StandardValidators.NON_BLANK_VALIDATOR)
        .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
        .build();

   // MOST IMPORTANT - This is our SLA to have a human record of acknowledgment not to promote private content.
   public static final PropertyDescriptor ACK_PRIVACY = new PropertyDescriptor.Builder()
        .name("Acknowledge Sanitization")
        .description("Processor names are included in in the metric as label values. By setting to true, you take responsibilty for ensuring all metric content is sanitized for privacy.")
        .allowableValues("true", "false")
        .defaultValue("false")
        .required(true)
        .build();

   // MOST IMPORTANT - This is our SLA to have a human record of acknowledgment not to promote private content.
   public static final PropertyDescriptor SIMULATION_MODE = new PropertyDescriptor.Builder()
        .name("Simulation mode")
        .description("Do not send metrics to Prometheus. Use nifi-app.log to view the metrics. This is a way of ensuring the metrics passed are sanitized for privacy.")
        .allowableValues("true", "false")
        .defaultValue("true")
        .required(true)
        .build();
   
   // The more samples, the less dynamic / volatile the slope computation.
   // We force Number-of-Trend-Samples to be >= 3 and < 1000.
   public static final PropertyDescriptor NUM_TREND_SAMPLES = new PropertyDescriptor.Builder()
        .name("Number of trend samples")
        .description("Linear Trend computation of slope and intercept requires a sufficient/balanced number of samples (>= 3 and < 1000).")
        .defaultValue("20")
        .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
        .required(true)
        .build();

   // NiFi properties list holder, compiled/filled at class load time (hence, static).
   private static final List<PropertyDescriptor> properties;

   // Order is significant, in terms of how items are placed into the class state
   // variable for 'properties'. This is the order in which they will appear on
   // the NiFi configuration properties edit page on the user interface.
   static
   {
      List<PropertyDescriptor> props = new ArrayList<>();
      props.add(ACK_PRIVACY);
      props.add(SIMULATION_MODE);
      props.add(NUM_TREND_SAMPLES);
      props.add(PROCESSOR_SITE);
      props.add(PROCESS_GROUP_FILTER);
      props.add(PROCESSOR_NAME_FILTER);
      props.add(PROCESSOR_TYPE_FILTER);
      props.add(PROM_ENDPOINT_URL);
      props.add(SSL_CONTEXT);
      properties = Collections.unmodifiableList(props);
   }

   // Class / state / properties

   /**
    * nifi instance moniker (root process group name)
    */
   protected String instanceMoniker = null;

   /**
    * output directory where metrics files are placed
    */
   protected String promUrl = null;

   /**
    * Initially, the starting process group to begin traversal, as configured
    * (default to all process groups using the 'root' canvas).
    *
    * When we find a matching process group, we change the value
    * of this property to be the process group identifier.
    */
   protected String process_group_filter = "root";

   /**
    * Processor type to match against.
    */
   protected String type = null;

   /**
    * Processor name (regex) to match against.
    */
   protected String name_expression = null;

   /**
    * Processor name as compiled (save compilation for efficiency and convenience).
    */
   protected Pattern name_pattern = null;

   /**
    * Used with math3.SimpleRegression Linear Trend computation, configurable
    * We force Number-of-Trend-Samples to be >= 3 and < 1000.
    */
   protected int numTrendSamples = 10;

   /**
    * A metric label that we only need to grab once (we'll grab it in the onScheduled() method)
    */
   protected String node = null;

   /**
    * We cannot determine 'site' by any other embedded nifi flow artifact (oh sure,
    * it could be a variable). But, nevertheless, site has to be provided extraneously.
    */
   protected String site = null;

   /**
    * The nifi data flow administrator must acknowledge and take responsibility
    * that their metrics are not beyond FIVE_EYES.
    */
   protected boolean privacy_ack = false;

   /**
    * Works in concert with privacy_ack to ensure that metrics do not exceed privacy constraints.
    * When true, metrics are not sent to prometheus, they are only logged to nifi-app.log.
    */
   protected boolean simulation = true;
   
   /**
    * Save property from onScheduled to be used in onTrigger
    */
   protected SSLContextService sslContextService = null;

   /**
    * Used when creating HttpContext, which is a thread local variable (i.e., volatile)
    * for the HTTPClient to obtain an available/reusable connection.
    */
   protected volatile Principal principal;

   // ------------ Summation metrics of potential use (or maybe not)

   protected long totalProcessor_bytes_read = 0L;
   protected long totalProcessor_bytes_received = 0L;
   protected long totalProcessor_bytes_sent = 0L;
   protected long totalProcessor_bytes_written = 0L;
   protected long totalProcessor_flow_files_received = 0L;
   protected long totalProcessor_flow_files_removed = 0L;
   protected long totalProcessor_flow_files_sent = 0L;
   protected long totalProcessor_input_bytes = 0L;
   protected long totalProcessor_input_count = 0L;
   protected long totalProcessor_output_bytes = 0L;
   protected long totalProcessor_output_count = 0L;

   /**
    * Used to hold underlying InputQueueBytes' time series data.
    * Used with SimpleRegression' Linear Trend algorithm;
    * We can not allocate this construct until run time ('er, onTrigger() method).
    * Map key is processor UUID.
    */
   protected Map<String, CircularFifoQueue<TimeSeriesPair>> srFifoInputQueueBytes = null;

   /**
    * Used to hold underlying InputQueueCount' time series data.
    * Used with SimpleRegression' Linear Trend algorithm;
    * We can not allocate this construct until run time ('er, onTrigger() method).
    * Map key is processor UUID.
    */
   protected Map<String, CircularFifoQueue<TimeSeriesPair>> srFifoInputQueueCount = null;

   /**
    * NiFi required method. No special processing, just a simple get accessor
    */
   @Override
   protected List<PropertyDescriptor> getSupportedPropertyDescriptors()
   {
      return properties;
   }

   /**
    * Save off the configuration properties (including regex evaluation).
    * Regarding validation/verification, we do not assume that onScheduled()
    * is invoked just ahead of onTrigger().
    *
    * We will do surface checking and so forth, and we will initialize
    * class state variables for posterity' and usability' sake, but we
    * consider all of the steps are preparatory, but not "finally".
    *
    * @param context
    */
   @OnScheduled
   public void onScheduled(final ConfigurationContext context)
   {
      try
      {
         privacy_ack = context.getProperty(ACK_PRIVACY).asBoolean();
         simulation = context.getProperty(SIMULATION_MODE).asBoolean();
         numTrendSamples = context.getProperty(NUM_TREND_SAMPLES).asInteger();
         site = context.getProperty(PROCESSOR_SITE).evaluateAttributeExpressions().getValue();
         promUrl = context.getProperty(PROM_ENDPOINT_URL).evaluateAttributeExpressions().getValue();
         process_group_filter = context.getProperty(PROCESS_GROUP_FILTER).evaluateAttributeExpressions().getValue();
         type = context.getProperty(PROCESSOR_TYPE_FILTER).evaluateAttributeExpressions().getValue();
         name_expression = context.getProperty(PROCESSOR_NAME_FILTER).evaluateAttributeExpressions().getValue();
         sslContextService = context.getProperty(SSL_CONTEXT).asControllerService(SSLContextService.class);

         getLogger().info("TRACE onScheduled() - promUrl{" + promUrl + "} processGroupFilter{" + process_group_filter + "} type{" + type + "} nameExpr{" + name_expression + "} site{" + site + "} numTrendSamples{" + numTrendSamples + "}");

         if (numTrendSamples < 3 || numTrendSamples > 1000) // sanity
         {
            numTrendSamples = 5; // reset to default
            getLogger().warn("numTrendSamples reset to default (cannot be < 3 or > 1000)");
         }

         if (srFifoInputQueueBytes == null) // only new'd the first time
         {
            srFifoInputQueueCount = new HashMap<>();
            srFifoInputQueueBytes = new HashMap<>();
         }

         if (name_expression != null && !name_expression.isEmpty()) // non-empty validator?
         {
            name_pattern = Pattern.compile(name_expression);
         }

         if (promUrl != null && !promUrl.isEmpty() && !promUrl.startsWith("http")) // rudimentary surface check
         {
            getLogger().error("Prometheus URL MUST start with 'http' -- reporting task service is disabled");
            promUrl = null;
         }

         if (promUrl != null && promUrl.startsWith("https") && sslContextService == null)
         {
            getLogger().error("Prometheus URL starts with 'https', but no sslContextService is provided -- reporting task service is disabled");
            promUrl = null;
         }

         try
         {
            node = InetAddress.getLocalHost().getHostName();
         }
         catch (Exception ex)
         {
            node = "unknown";
            getLogger().warn("Unable to get hostname exception.", ex);
         }
      }
      catch (Exception e)
      {
         getLogger().error("OnScheduled() exception", e);
      }
   }

   /**
    * Currently a trace log event, but we may need to trap task stop
    * if we have concurrent threads running.
    *
    * @throws Exception
    */
   @OnStopped
   public void OnStopped() throws Exception
   {
      getLogger().debug("TRACE - OnStopped()");

      // presume onStopped is not the same as "scheduled run completed"
      if (srFifoInputQueueCount != null) { srFifoInputQueueCount.clear(); }
      if (srFifoInputQueueBytes != null) { srFifoInputQueueBytes.clear(); }
   }

   /**
    * Currently a trace log event, but we may need to trap shutdown
    * if we have temporal processes/threads/state that need to clean up.
    *
    * @throws Exception
    */
   @OnShutdown
   public void onShutDown() throws Exception
   {
      getLogger().debug("TRACE - OnShutDown()");
      if (srFifoInputQueueCount != null) { srFifoInputQueueCount.clear(); }
      if (srFifoInputQueueBytes != null) { srFifoInputQueueBytes.clear(); }
   }

   /**
    * onTrigger() is invoked on schedule.
    *
    * Obtain the specified process group and proceed downward from there...
    *
    * Based on whether we are in a cluster or standalone, we will configure
    * reporting identification labels aptly (namely, our instance moniker).
    *
    * We validate/verify some of the configuration properties at this juncture,
    * along with the "are-you-sure", and ignore any processing if we're not
    * happy with things. We could write custom validators and we could do some of
    * the V&V elsewhere, but -- programmatically -- we would still wind up coding
    * these V&V tests herein anyway, since things can change between configuration
    * property entry' time and onTrigger() schedule' time.
    *
    * @param context used to traverse process groups from the root canvas (or other specified starting point) recursively downward.
    */
   @Override
   public void onTrigger(ReportingContext context)
   {
      getLogger().debug("TRACE - onTrigger() - promUrl{" + promUrl + "} process-group-filter{" + process_group_filter + "} type{" + type + "} nameExpr{" + name_expression + "} ClusterNodeId{" + context.getClusterNodeIdentifier() + "}");

      if (promUrl != null && !promUrl.isEmpty() && !promUrl.startsWith("http")) // required and rudimentary surface check
      {
         getLogger().error("Prometheus URL MUST start with 'http' -- reporting task service is efectively disabled");
         promUrl = null;
      }
      if (promUrl != null && promUrl.startsWith("https") && sslContextService == null)
      {
         getLogger().error("Prometheus URL starts with 'https', but no sslContextService is provided -- reporting task service is disabled");
         promUrl = null;
      }

      if (promUrl != null && promUrl.endsWith("/")) // remove the trailing slash (we tack it on later)
      {
         promUrl = promUrl.substring(0, promUrl.length() - 1);
      }

      if (srFifoInputQueueCount == null) { srFifoInputQueueCount = new HashMap<>(); } // sanity
      if (srFifoInputQueueBytes == null) { srFifoInputQueueBytes = new HashMap<>(); } // sanity

      /**
       * For some reason, the reporting task will start, even though the node is not connected
       * (in a cluster). We'll report erroneous metrics if we're not connected.
       *
       * There appears to be no other way for a reporting task to get at "node status", other than
       * below scheme, which is hardly foolproof. Nodes themselves are fooled as to connection status.
       */
      boolean connected = false;
      if (!context.isClustered())
      {
         connected = true; // we are running in a standalone configuration (to the best of our knowledge, noting we could be fooled).
      }
      else if (context.getClusterNodeIdentifier() != null) // another "to the best of our knowledge" assumptions.
      {
         connected = true;
      }
      else // let's log that we're not connected
      {
         getLogger().warn("The cluster is not connected. We'll not report metrics until such time as we are connected.");
      }

      if (!privacy_ack)
      {
         getLogger().warn("The privacy acknowledgment has not been set. ReportingTask is effectively disabled.");
      }

      /**
       * Transform process group filter from name to identifier (this is a side effect, as we modify class state).
       *
       * Note that the literal 'root' is the only hard wired moniker that works as a group status retrieval identifier.
       */
      ProcessGroupStatus rootPGS = context.getEventAccess().getGroupStatus("root"); // we'll be using this in a few places

      // "root" canvas is a special case in terms of process group traversal.
      // If the process group filter is "root", we have to preset the search/match.
      // We can use either rootPGS' 'name' or 'id' -- might was well use the 'id'
      if (rootPGS != null && // sanity
          "root".contentEquals(process_group_filter)) // we are looking to match "root" (that is, the entire instance)
      {
         process_group_filter = rootPGS.getId();
      }

      boolean starting_process_group_filter_is_valid = matchAgainstProcessGroupFilter(context, rootPGS);

      if (!starting_process_group_filter_is_valid)
      {
         getLogger().warn("Process group filter -- " + process_group_filter + " -- does not exist. Ignored.");
      }

      // Can we proceed?
      if (privacy_ack &&  // nifi data flow administrator has acknowledged their responsibility for metric content to follow privacy constraints.
          starting_process_group_filter_is_valid &&
          connected && // either standalone or we have obtained our cluster identifier (we can be fooled, however)
          promUrl != null && !promUrl.isEmpty() && // sanity
          type != null && !type.isEmpty() && // sanity / non-empty validator?
          name_pattern != null) // sanity
      {
         // instanceMoniker: we need something unique and non-null
         // instanceMoniker will, after the first time, be non-null/non-empty
         if (instanceMoniker == null)
         {
            if (rootPGS != null)
            {
               instanceMoniker = rootPGS.getName().replace("[^a-zA-Z0-9]", "-").replace(" ", "-");
               // we'll settle up with other issues below...
            }
         }

         // "NiFi Flow" is not an acceptable default instanceMoniker for our purposes.
         if ((instanceMoniker == null || instanceMoniker.equalsIgnoreCase("NiFi Flow"))
              && context.isClustered())
         {
            // WARN: getClusterNodeIdentifier() has a bug -- the cluster node identifier does
            // not update when the string is changed in the NiFi UI (at least, for standalone).
            // In this situation, you must restart the instance to obtain the current value.

            instanceMoniker = context.getClusterNodeIdentifier(); // returns non-null when clustered (and connected)
         }
         if (instanceMoniker == null || instanceMoniker.equalsIgnoreCase("NiFi Flow"))
         {
            instanceMoniker = node; // we're single node, we'll just use the node specification as our instance
         }
         if (instanceMoniker == null || instanceMoniker.isEmpty())
         {
            instanceMoniker = "unknown"; // if all else fails (versus shutting down the whole operation)
         }

         String[] formulatedMetrics = new String[1]; // simple push/maintain/throughout-stack mechanism
         formulatedMetrics[0] = ""; // initialize to non-null-yet-empty

         /**
          * First, regardless of processor and process group reporting, we will always report
          * the JVM metrics for our node.
          */
         formulateJvmMetrics(context, formulatedMetrics);

         /**
          * The real body of metrics gathering work occurs within reportOnGroup()
          */
         reportOnGroup(context, formulatedMetrics, process_group_filter);

         // Now we can push the metrics out...

         if (!formulatedMetrics[0].isEmpty()) // we have metrics to push (we should have one or more JVM metrics)
         {
            try // guard against SSL/HTTP/URL-encode/NPE exceptions, etc
            {
               // We could formulate 'system' elsewhere, but we'd wind up with one more class/state property that way.
               String system = instanceMoniker;
               if (context.isClustered())
               {
                  system += "-" + context.getClusterNodeIdentifier();
               }
               // TODO change all the rest of the metric labels over to URL (easier said than done)
               String formulatedURL = "/site/" + URLEncoder.encode(site, "UTF-8") +
                    "/system/" + URLEncoder.encode(system, "UTF-8");

               URL url = new URL(promUrl + formulatedURL); // used as a verifier

               if (simulation)
               {
                  getLogger().info("TRACE - URL (ENCODED): " + url); // this is fairly useful as an INFO
                  getLogger().info("TRACE - metric (string): " + formulatedMetrics[0]); // this is fairly useful as an INFO
               }

               if (!simulation)
               {
                  HttpClientBuilder httpClientBuilder = HttpClients.custom();
                  if (formulatedURL.startsWith("https") && sslContextService != null) // latter check is sanity
                  {
                     SSLContext sslContext = createSSLContext(sslContextService);
                     final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);
                     httpClientBuilder = httpClientBuilder.setSSLSocketFactory(sslsf);
                  }
                  CloseableHttpClient httpClient = httpClientBuilder.build();
                  HttpPost httpPost = new HttpPost(url.toString());
                  HttpEntity httpEntity = new StringEntity(formulatedMetrics[0], ContentType.TEXT_PLAIN);
                  httpPost.setEntity(httpEntity);
                  HttpResponse httpResponse = httpClient.execute(httpPost);

                  /**
                   * A "200 OK" response code only signifies a successful transport handshake.
                   * Hence, we log, as "TRACE/INFO", the metrics content above, so that we can see what we sent.
                   */
                  if (httpResponse.getStatusLine().getStatusCode() == 200) // even this is not indicative of success
                  {
                     getLogger().info("TRACE - HttpResponse.statusLine: " + httpResponse.getStatusLine());
                  }
                  else
                  {
                     getLogger().warn("TRACE - Unable to post metrics to prometheus, http response: " + httpResponse.getStatusLine());
                  }
               }
            }
            catch (Exception ex)
            {
               getLogger().warn("Unable to post metrics to prometheus due to exception.", ex);
            }
         } // end block we have metrics to push
      }
      else
      {
         getLogger().warn("OnTrigger() cannot continue as parametric arguments are null/empty/invalid. Please double check configuration properties, NiFi cluster/node status, and log events (warning or error, in particular) for more specifics.");
      }
   }

   /**
    * Given a process group handle, traverse the nested hierarchy looking for a match against
    * the process_group_filter "name" provided via the ReportingTask configuration property set)
    * (first, we attempt the match against the current level provided, traversing deeper otherwise).
    * Note we traverse depth-first, which doesn't otherwise matter unless there are multiple process groups
    * with the same name (a condition we are not expressly handling).
    *
    * YELLOW-37! Side effect: We change process_group_filter class state from "name" to "id"; If we don't
    * find a match, then we leave the original value of process_group_filter unchanged (for log purposes).
    * @param context presume non-null
    * @param currentLevelPGS handle to process group status object at the current level (starting at 'root' / top)
    * @return true or false if we find a match in the hierarchy of the provided group to search
    */
   protected boolean matchAgainstProcessGroupFilter(ReportingContext context, ProcessGroupStatus currentLevelPGS)
   {
      boolean rtn = false;

      if (context != null && currentLevelPGS != null) // sanity
      {
         // If our current level is the match, we are done...
         if (process_group_filter.equals(currentLevelPGS.getName()) || // initially,  we search by name.
             process_group_filter.equals(currentLevelPGS.getId()))     // thereafter, we have changed the state to be the actual identifier
         {
            rtn = true;

            process_group_filter = currentLevelPGS.getId(); // only redundant if we already found the match

            getLogger().debug("TRACE - matchAgainstProcessGroupFilter() - match ID{" + process_group_filter + "}");
         }
         else // current level doesn't match, let's traverse the process groups at the next level...
         {
            for (ProcessGroupStatus pgs : currentLevelPGS.getProcessGroupStatus())
            {
               rtn = matchAgainstProcessGroupFilter(context, pgs); // recursive method invocation

               if (rtn) { break; } // we found a match and set ID, so break out of loop
            } // end loop through next level of process groups
         } // end block traverse the next level process groups
      } // end block method arguments are sane

      return rtn;
   }

   /**
    * Given a process group name (starting at the top with 'root', typically), recursively process all child
    * process groups, reporting processor efficiency status as matching the provided PROCESSOR_TYPE and
    * NAME filter properties. The way we coded this, we proceed depth-then-breadth (it doesn't matter,
    * at the end-of-the-day, so to speak, because arrangement is ultimately handled when we work in
    * grafana).
    *
    * @param formulatedMetrics simple push/maintain/throughout-stack mechanism
    * @param context           Used to traverse the process groups from the root canvas, recursively.
    * @param group             the process group identifier (not name, but ID) that we are currently traversing
    */
   protected void reportOnGroup(ReportingContext context, String[] formulatedMetrics, String group)
   {
      if (context != null && formulatedMetrics != null && group != null && !group.isEmpty()) // sanity
      {
         try
         {
            ProcessGroupStatus currentLevelPGS = context.getEventAccess().getGroupStatus(group);

            if (currentLevelPGS != null) // sanity
            {
               getLogger().debug("TRACE reportOnGroup() - group: " + group + " / group status name: " + currentLevelPGS.getName() + " / group status id: " + currentLevelPGS.getId());

               // We go depth first (no particular reason, just the paradigm we decided to follow)...
               for (ProcessGroupStatus pgs : context.getEventAccess().getGroupStatus(group).getProcessGroupStatus())
               {
                  getLogger().debug("TRACE reportOnGroup() - group: " + group + " / process group status name: " + pgs.getName() + " / process group status id: " + pgs.getId());

                  reportOnGroup(context, formulatedMetrics, pgs.getId()); // recursive, proceeding depth-first
               }

               // Next, report the matching processors that we may (or might not) match in our current level of process group
               reportProcessorsInGroup(context, formulatedMetrics, currentLevelPGS); // in our group at the current process group hierarchy level
            } // end block we have process groups to traverse
            else // we should always be able to obtain the current process group level using the group-identifier provided.
            {
               getLogger().warn("reportOnGroup() - unable to get group status for groupId: " + group);
            }
         }
         catch (Exception e)
         {
            getLogger().error("reportOnGroup(" + group + ") exception", e);
         }
      }
      else
      {
         getLogger().warn("reportOnGroup() cannot continue as parametric arguments are null/empty");
      }
   }

   /**
    * Given a process group, traverse processors and report their efficiencies (that is,
    * for processors that match our filter by type and name expression).
    *
    * Note that we are reporting processor metrics at the specified process group level in
    * the process group hierarchy. There is no "proceed downward to lower-levels" logic herein
    * (the recursive traversal logic occurs a la the reportOnGroup() method).
    *
    * @param formulatedMetrics simple push/maintain/throughout-stack mechanism
    * @param context           currently not used
    * @param pgs               The current process group handle that we are traversing
    */
   protected void reportProcessorsInGroup(ReportingContext context, String[] formulatedMetrics, ProcessGroupStatus pgs)
   {
      try // the only likely trapped exception would be NPE, but for posterity' sake...
      {
         for (ProcessorStatus ps : pgs.getProcessorStatus())
         {
            String processorType = ps.getType(); // convenience
            String processorName = ps.getName(); // convenience

            getLogger().debug("TRACE reportProcessorsInGroup() - processor{nameExpr{" + processorName + "} type{" + processorType + "} process group name{" + pgs.getName() + "} process group id{" + pgs.getId() + "}");

            Matcher matcher = name_pattern.matcher(processorName); // name_pattern is presumed to be non-null by the time we reach this juncture

            if (processorType != null && // sanity (don't want an NPE and it is not a match, otherwise)
                processorType.equals(type) && matcher.matches()) // we have a match on processor type and processor name
            {
               getLogger().debug("TRACE reportProcessorsInGroup() - processor is running and type/name match our filter");

               reportProcessorEfficiencyMetrics(context, formulatedMetrics, pgs, ps); // reporting is done in a sub-method for the sake of code readability
            } // end block processor is running
         } // end loop through processors in process group
      }
      catch (Exception ex)
      {
         getLogger().warn("reportProcessorsInGroup(" + pgs + ") exception", ex);
      }
   }

   /**
    * We are handed a running processor for which matches our filter criteria.
    * Let's report the processor efficiency metrics
    *
    * @param context           currently unused
    * @param formulatedMetrics simple push/maintain/throughout-stack mechanism
    * @param pgs               passed in to be reported into the metric labeling
    * @param ps                handle to the processor to report metrics on
    */
   protected void reportProcessorEfficiencyMetrics(ReportingContext context, String[] formulatedMetrics, ProcessGroupStatus pgs, ProcessorStatus ps)
   {
      try
      {
         if (pgs != null && ps != null && promUrl != null && !promUrl.isEmpty()) // sanity
         {
            RunStatus processorStatus = ps.getRunStatus(); // convenience
            if (processorStatus == RunStatus.Running)
            {
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_run_status", 1);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_active_thread_count", ps.getActiveThreadCount());
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_average_lineage_seconds", ps.getAverageLineageDuration(TimeUnit.SECONDS)); // long
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_processing_nanos", ps.getProcessingNanos()); // long
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_bytes_read", ps.getBytesRead()); // long
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_bytes_received", ps.getBytesReceived()); // long
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_bytes_sent", ps.getBytesSent()); // long
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_bytes_written", ps.getBytesWritten()); // long
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_flow_files_received", ps.getFlowFilesReceived()); // int
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_flow_files_removed", ps.getFlowFilesRemoved()); // int
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_flow_files_sent", ps.getFlowFilesSent()); // int
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_input_bytes", ps.getInputBytes()); // long
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_input_count", ps.getInputCount()); // int
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_output_bytes", ps.getOutputBytes()); // long
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_output_count", ps.getOutputCount()); // int
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_terminated_thread_count", ps.getTerminatedThreadCount()); // int

               totalProcessor_bytes_read += ps.getBytesRead();
               totalProcessor_bytes_received += ps.getBytesReceived();
               totalProcessor_bytes_sent += ps.getBytesSent();
               totalProcessor_bytes_written += ps.getBytesWritten();
               totalProcessor_flow_files_received += ps.getFlowFilesReceived();
               totalProcessor_flow_files_removed += ps.getFlowFilesRemoved();
               totalProcessor_flow_files_sent += ps.getFlowFilesSent();
               totalProcessor_input_bytes += ps.getInputBytes();
               totalProcessor_input_count += ps.getInputCount();
               totalProcessor_output_bytes += ps.getOutputBytes();
               totalProcessor_output_count += ps.getOutputCount();

               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_bytes_read", totalProcessor_bytes_read);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_bytes_received", totalProcessor_bytes_received);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_bytes_sent", totalProcessor_bytes_sent);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_bytes_written", totalProcessor_bytes_written);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_flow_files_received", totalProcessor_flow_files_received);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_flow_files_removed", totalProcessor_flow_files_removed);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_flow_files_sent", totalProcessor_flow_files_sent);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_input_bytes", totalProcessor_input_bytes);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_input_count", totalProcessor_input_count);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_output_bytes", totalProcessor_output_bytes);
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_total_output_count", totalProcessor_output_count);

               formulateQueueMetrics(context, formulatedMetrics, pgs, ps);
            }
            else // not running
            {
               formulateMetric(context, formulatedMetrics, pgs, ps, "nifi_processor_run_status", 0);
            }
         } // end sanity block we have a non-null processor handle
      }
      catch (Exception ex)
      {
         getLogger().warn("reportProcessorEfficiencyMetrics() exception", ex);
      }
   }

   /**
    * Given a process group handle and a processor handle, do a cross join between the two,
    * on "Connections", and formulate all the metric strings to go out the door.
    *
    * @param context           not used, but passed along in case we might need to use it in the future
    * @param formulatedMetrics in and out, we take what we have, add to it and pass it back (well, it's on the stack)
    * @param pgs               handle to the process group
    * @param ps                handle to the processor we are looking to build connection metrics for
    * @throws UnsupportedEncodingException hope this doesn't happen (kind of non-garbage-in situation)
    */
   protected void formulateQueueMetrics(ReportingContext context, String[] formulatedMetrics, ProcessGroupStatus pgs, ProcessorStatus ps) throws UnsupportedEncodingException
   {
      String processorId = ps.getId();
      getLogger().debug("TRACE getQueueCounts() - Processor{" + ps.getName() + "} id{" + processorId + "} groupId{" + ps.getGroupId() + "}");

      Collection<ConnectionStatus> connStatColl = pgs.getConnectionStatus();
      for (ConnectionStatus connStat : connStatColl)
      {
         String queueName = null;
         String queueSide = null;
         String metricName = null;
         long metricValue = 0;

         // Is this an input queue or an output queue?
         if (processorId != null /* sanity */ && processorId.equalsIgnoreCase(connStat.getDestinationId())) // input queue
         {
            queueSide = "input"; // input queue:
            queueName = "input"; // input queues do not have a queue name
            getLogger().debug("TRACE INPUT QUEUE - groupName{" + pgs.getName() + "} connection{" + connStat + "}");
            
            CircularFifoQueue<TimeSeriesPair> localFifoInputQueueBytes = srFifoInputQueueBytes.get(processorId);
            if (localFifoInputQueueBytes == null)
            {
               localFifoInputQueueBytes = new CircularFifoQueue<TimeSeriesPair>(numTrendSamples);
               srFifoInputQueueBytes.put(processorId, localFifoInputQueueBytes);
            }
            CircularFifoQueue<TimeSeriesPair> localFifoInputQueueCount = srFifoInputQueueCount.get(processorId);
            if (localFifoInputQueueCount == null)
            {
               localFifoInputQueueCount = new CircularFifoQueue<TimeSeriesPair>(numTrendSamples);
               srFifoInputQueueCount.put(processorId, localFifoInputQueueCount);
            }

            // So, this may seem odd, that we're calling "getOutputBlah()" versus "getInputBlah()",
            // but the output side of the "input queue" is consistent and non-zero.
            metricValue = connStat.getOutputBytes();
            long epochTime = System.currentTimeMillis() / 1000;
            TimeSeriesPair tsp = new TimeSeriesPair(epochTime, metricValue);
            localFifoInputQueueBytes.add(tsp);
            metricValue = connStat.getOutputCount();
            tsp = new TimeSeriesPair(epochTime, metricValue);
            localFifoInputQueueCount.add(tsp);

            // There is one and only one input queue for a processor.
            // We can, thus, produce the SimpleRegressions if we've got enough samples...

            if (localFifoInputQueueBytes.isAtFullCapacity()) // only need to check one of them
            {
               final SimpleRegression sr = new SimpleRegression(true);
               localFifoInputQueueBytes.forEach((k) -> {
                  sr.addData(k.getKey(), k.getValue());
               } );
               metricName = "nifi_processor_input_queue_bytes_slope";
               metricValue = (long) sr.getSlope();
               formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);
               metricName = "nifi_processor_input_queue_bytes_intercept";
               metricValue = (long) sr.getIntercept();
               if (Double.isNaN((metricValue))) { metricValue = 0; }
               formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);

               final SimpleRegression sr2 = new SimpleRegression(true);
               localFifoInputQueueCount.forEach((k) -> {
                  sr2.addData(k.getKey(), k.getValue());
               } );
               metricName = "nifi_processor_input_queue_count_slope";
               metricValue = (long) sr2.getSlope();
               formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);
               metricName = "nifi_processor_input_queue_count_intercept";
               metricValue = (long) sr2.getIntercept();
               if (Double.isNaN((metricValue))) { metricValue = 0; }
               formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);
            } // end block the fifo queues have enough samples
         }
         else if (processorId != null /* sanity */ && processorId.equalsIgnoreCase(connStat.getSourceId())) // output queue
         {
            queueSide = "output"; // output queue
            queueName = connStat.getName(); //if it's null/empty, we'll skip it
            getLogger().debug("TRACE OUTPUT QUEUE - groupName{" + pgs.getName() + "} connection{" + connStat + "}");
         }

         if (queueName != null && !queueName.isEmpty()) // this is a metric for us, and queueSide is also set
         {
            metricName = "nifi_processor_input_queue_count";
            metricValue = connStat.getInputCount();
            formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);
            metricName = "nifi_processor_input_queue_bytes";
            metricValue = connStat.getInputBytes();
            formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);
            metricName = "nifi_processor_output_queue_count";
            metricValue = connStat.getOutputCount();
            formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);
            metricName = "nifi_processor_output_queue_bytes";
            metricValue = connStat.getOutputBytes();
            formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);
            metricName = "nifi_processor_queue_size_count";
            metricValue = connStat.getQueuedCount();
            formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);
            metricName = "nifi_processor_queue_size_bytes";
            metricValue = connStat.getQueuedBytes();
            formulateQueueMetric(formulatedMetrics, metricName, metricValue, queueName, queueSide, pgs, ps);

            // TODO (to be determined): connStat.getPredictions().*
         }
      }
   }

   /**
    * Formulate a metric for a processor queue (provided), with node and instanceMoniker
    * being grabbed from our class state and append to our master set of metrics (provided, in/out).
    *
    * @param formulatedMetrics our master set of metrics (in string form with newlines)
    * @param metricName        provided
    * @param metricValue       provided
    * @param queueName         provided
    * @param queueSide         provided
    * @param pgs               process group handle - used to obtain name
    * @param ps                processor handle - used to obtain name and type
    */
   protected void formulateQueueMetric(String[] formulatedMetrics, String metricName, long metricValue, String queueName, String queueSide, ProcessGroupStatus pgs, ProcessorStatus ps)
   {
      String formulatedMetric = formulatedMetrics[0] + metricName +
           "{process_group=\"" + pgs.getName() +
           "\",processor=\"" + ps.getName() +
           "\",processor_type=\"" + ps.getType() +
           "\",node=\"" + node +
           "\",instance=\"" + instanceMoniker +
           "\",queue_name=\"" + queueName +
           "\",queue_side=\"" + queueSide +
           "\"} " + metricValue + System.lineSeparator(); // no timing appended
      formulatedMetrics[0] = formulatedMetric; // reset stack for return value
   }

   /**
    * Formulate metric in Prometheus' form and write to provided file path (open / append / write / close).
    * Hostname and timestamp come from Java.
    *
    * @param context           Used to obtain "system" a la context.getClusterNodeIdentifier()
    * @param formulatedMetrics simple push/maintain/throughout-stack mechanism
    * @param pgs               Used to extract process group name (a control element -- 'er, label), non-null
    * @param ps                Used to extract process control labels, non-null
    * @param metricName        self explanatory, non-null/non-empty
    * @param metricValue       self explanatory, numeric
    */
   protected void formulateMetric(ReportingContext context, String[] formulatedMetrics, ProcessGroupStatus pgs, ProcessorStatus ps, String metricName, long metricValue) throws UnsupportedEncodingException
   {
      if (pgs != null && ps != null && // sanity
           formulatedMetrics[0] != null && // sanity
           metricName != null && !metricName.isEmpty()) // sanity
      {
         String formulatedMetric = formulatedMetrics[0] + metricName +
              "{process_group=\"" + pgs.getName() +
              "\",processor=\"" + ps.getName() +
              "\",processor_type=\"" + ps.getType() +
              "\",node=\"" + node +
              "\",instance=\"" + instanceMoniker +
              "\"} " + metricValue + System.lineSeparator(); // no timing appended
         formulatedMetrics[0] = formulatedMetric; // reset stack for return value
      } // end block method parametric arguments are sane
   }

   /**
    * Capture JVM memory and cpu statistics
    *
    * We have total mem, max mem (what's the diff?) and free mem
    * (for which we can compute used/available and percentages).
    *
    * We decided to report: free/used/avail (and leave percent and
    * the others for the display side to fiddle with).
    *
    * For health, it's not quite about percent used as what's actually
    * available.
    *
    * There is also "available processors", but we'll discount that.
    *
    * @param context           not currently used
    * @param formulatedMetrics In/Out
    */
   @SuppressWarnings("restriction")
   protected void formulateJvmMetrics(ReportingContext context, String[] formulatedMetrics)
   {
      String metricName = null;
      long metricValue = 0;

      Runtime runtime = Runtime.getRuntime();
      metricName = "nifi_instance_free_memory";
      metricValue = runtime.freeMemory(); // this can be a bit "fuzzy"
      formulateJvmMetric(formulatedMetrics, metricName, metricValue);
      metricName = "nifi_instance_used_memory";
      metricValue = runtime.totalMemory() - runtime.freeMemory(); // ditto, but less fuzzy in a way (long story)
      formulateJvmMetric(formulatedMetrics, metricName, metricValue);

      // available is the most key memory metric for determining (future) health.
      // It is calculated as maxmemory (that is, -Xmx) minus used memory (calculated above).
      metricName = "nifi_instance_available_memory";
      metricValue = runtime.maxMemory() - metricValue;
      formulateJvmMetric(formulatedMetrics, metricName, metricValue);

      /**
       * For CPU metrics, we intend to use the com.sun.management variant
       * which is fully expected to exist on centos.
       *
       * However, for programmatic purposes, we make this conditional for
       * posterity ('er, platform independence). Mileage could vary, but
       * we fully expect to be working with "osExtended".
       */
      OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
      com.sun.management.OperatingSystemMXBean osExtended = null;
      try
      {
         osExtended = (com.sun.management.OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
      }
      catch (Exception ex) { } // class cast exception, ignore

      if (osExtended != null)
      {
         metricName = "nifi_instance_cpu_time";
         metricValue = osExtended.getProcessCpuTime();
         formulateJvmMetric(formulatedMetrics, metricName, metricValue);

         metricName = "nifi_instance_cpu_load";
         metricValue = Double.valueOf(osExtended.getProcessCpuLoad() * 100).longValue();
         formulateJvmMetric(formulatedMetrics, metricName, metricValue);
      }
      else // java.lang.Management
      {
         metricName = "nifi_instance_system_load_average";
         metricValue = Double.valueOf(os.getSystemLoadAverage()).longValue();
         formulateJvmMetric(formulatedMetrics, metricName, metricValue);
      }
   }

   /**
    * @param formulatedMetrics
    * @param metricName
    * @param metricValue
    */
   protected void formulateJvmMetric(String[] formulatedMetrics, String metricName, long metricValue)
   {
      if (formulatedMetrics[0] != null && // sanity
           metricName != null && !metricName.isEmpty()) // sanity
      {
         String formulatedMetric = formulatedMetrics[0] + metricName +
              "{node=\"" + node +
              "\",instance=\"" + instanceMoniker +
              "\"} " + metricValue + System.lineSeparator(); // no timing appended
         formulatedMetrics[0] = formulatedMetric; // reset stack for return value
      }
   }

   /**
    * Following along with NiFi' HTTPPost.java, use the SSLContextService to create our SSLContext,
    * pulling and passing along all the embedded/provided truststore-and-keystore elements.
    *
    * @param service the ssl context service, referenced via NiFi property, provides the credentials
    *                for truststore and keystore
    * @return
    * @throws KeyStoreException
    * @throws IOException
    * @throws NoSuchAlgorithmException
    * @throws CertificateException
    * @throws KeyManagementException
    * @throws UnrecoverableKeyException
    */
   protected SSLContext createSSLContext(final SSLContextService service)
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException
   {
      SSLContextBuilder builder = SSLContexts.custom();
      final String trustFilename = service.getTrustStoreFile();
      if (trustFilename != null)
      {
         final KeyStore truststore = KeyStoreUtils.getTrustStore(service.getTrustStoreType());
         try (final InputStream in = new FileInputStream(new File(service.getTrustStoreFile())))
         {
            truststore.load(in, service.getTrustStorePassword().toCharArray());
         }
         builder = builder.loadTrustMaterial(truststore, new TrustSelfSignedStrategy());
      }

      final String keyFilename = service.getKeyStoreFile();
      if (keyFilename != null)
      {
         final KeyStore keystore = KeyStoreUtils.getKeyStore(service.getKeyStoreType());
         try (final InputStream in = new FileInputStream(new File(service.getKeyStoreFile())))
         {
            keystore.load(in, service.getKeyStorePassword().toCharArray());
         }
         builder = builder.loadKeyMaterial(keystore, service.getKeyStorePassword().toCharArray());
         final String alias = keystore.aliases().nextElement();
         final Certificate cert = keystore.getCertificate(alias);
         if (cert instanceof X509Certificate)
         {
            principal = ((X509Certificate) cert).getSubjectDN();
         }
      }

      builder = builder.setProtocol(service.getSslAlgorithm());

      final SSLContext sslContext = builder.build();
      return sslContext;
   }
}

