package Mail::Milter::Authentication::Metric::Grafana;
use strict;
use warnings;
use version; our $VERSION = version->declare('v1.1.3');

use JSON;

sub get_Base {
    return '
{
   "title" : "Authentication Milter",
   "schemaVersion" : 14,
   "__requires" : [
      {
         "id" : "grafana",
         "name" : "Grafana",
         "type" : "grafana",
         "version" : "4.2.0"
      },
      {
         "version" : "",
         "type" : "panel",
         "name" : "Graph",
         "id" : "graph"
      },
      {
         "name" : "Prometheus",
         "id" : "prometheus",
         "version" : "1.0.0",
         "type" : "datasource"
      }
   ],
   "graphTooltip" : 0,
   "id" : null,
   "tags" : [
      "AuthenticationMilter"
   ],
   "hideControls" : false,
   "timepicker" : {
      "refresh_intervals" : [
         "5s",
         "10s",
         "30s",
         "1m",
         "5m",
         "15m",
         "30m",
         "1h",
         "2h",
         "1d"
      ],
      "time_options" : [
         "5m",
         "15m",
         "1h",
         "6h",
         "12h",
         "24h",
         "2d",
         "7d",
         "30d"
      ]
   },
   "rows" : [],
   "timezone" : "browser",
   "links" : [],
   "refresh" : false,
   "time" : {
      "from" : "now-1h",
      "to" : "now"
   },
   "templating" : {
      "list" : [
         {
            "current" : {},
            "label" : null,
            "hide" : 0,
            "type" : "query",
            "tagValuesQuery" : "",
            "sort" : 1,
            "tags" : [],
            "options" : [],
            "datasource" : "${DS_PROMETHEUS}",
            "query" : "label_values(authmilter_uptime_seconds_total, node)",
            "tagsQuery" : "",
            "allValue" : null,
            "includeAll" : true,
            "multi" : true,
            "useTags" : false,
            "name" : "node",
            "regex" : "",
            "refresh" : 1
         },
         {
            "datasource" : null,
            "current" : {
               "value" : "1m",
               "text" : "1m"
            },
            "query" : "1m,10m,30m,1h,6h,12h,1d,7d,14d,30d",
            "label" : "",
            "auto_min" : "10s",
            "auto_count" : 30,
            "auto" : false,
            "type" : "interval",
            "hide" : 0,
            "name" : "ratetime",
            "options" : [
               {
                  "text" : "1m",
                  "selected" : true,
                  "value" : "1m"
               },
               {
                  "value" : "10m",
                  "text" : "10m",
                  "selected" : false
               },
               {
                  "value" : "30m",
                  "selected" : false,
                  "text" : "30m"
               },
               {
                  "selected" : false,
                  "text" : "1h",
                  "value" : "1h"
               },
               {
                  "value" : "6h",
                  "selected" : false,
                  "text" : "6h"
               },
               {
                  "text" : "12h",
                  "selected" : false,
                  "value" : "12h"
               },
               {
                  "value" : "1d",
                  "selected" : false,
                  "text" : "1d"
               },
               {
                  "selected" : false,
                  "text" : "7d",
                  "value" : "7d"
               },
               {
                  "value" : "14d",
                  "selected" : false,
                  "text" : "14d"
               },
               {
                  "value" : "30d",
                  "text" : "30d",
                  "selected" : false
               }
            ],
            "refresh" : 2,
            "includeAll" : false,
            "multi" : false
         }
      ]
   },
   "style" : "dark",
   "version" : 56,
   "editable" : true,
   "__inputs" : [
      {
         "pluginName" : "Prometheus",
         "type" : "datasource",
         "description" : "",
         "pluginId" : "prometheus",
         "label" : "Prometheus",
         "name" : "DS_PROMETHEUS"
      }
   ],
   "gnetId" : null,
   "annotations" : {
      "list" : []
   }
}
';
}

sub get_RowThroughput {
    return '
{
   "repeatRowId" : null,
   "panels" : [
      {
         "nullPointMode" : "connected",
         "id" : 9,
         "error" : false,
         "tooltip" : {
            "value_type" : "cumulative",
            "sort" : 2,
            "msResolution" : false,
            "shared" : true
         },
         "bars" : false,
         "thresholds" : [],
         "fill" : 1,
         "timeShift" : null,
         "targets" : [
            {
               "legendFormat" : "{{ result }}",
               "metric" : "authmilter_mail_",
               "expr" : "sum(rate(authmilter_mail_processed_total{node=~\"$node\"}[$ratetime])) by(result)",
               "step" : 4,
               "interval" : "",
               "refId" : "A",
               "intervalFactor" : 2
            }
         ],
         "span" : 12,
         "editable" : true,
         "type" : "graph",
         "steppedLine" : false,
         "pointradius" : 5,
         "aliasColors" : {},
         "xaxis" : {
            "show" : true,
            "name" : null,
            "mode" : "time",
            "values" : []
         },
         "grid" : {},
         "renderer" : "flot",
         "linewidth" : 2,
         "yaxes" : [
            {
               "min" : null,
               "show" : true,
               "label" : null,
               "format" : "short",
               "max" : null,
               "logBase" : 1
            },
            {
               "min" : null,
               "show" : true,
               "logBase" : 1,
               "max" : null,
               "format" : "short",
               "label" : null
            }
         ],
         "percentage" : false,
         "links" : [],
         "legend" : {
            "max" : false,
            "show" : true,
            "min" : false,
            "current" : false,
            "values" : false,
            "hideZero" : true,
            "total" : false,
            "avg" : false
         },
         "points" : false,
         "lines" : true,
         "title" : "Emails processed rate by result",
         "datasource" : "${DS_PROMETHEUS}",
         "stack" : false,
         "seriesOverrides" : [],
         "timeFrom" : null
      },
      {
         "aliasColors" : {},
         "pointradius" : 5,
         "xaxis" : {
            "show" : true,
            "name" : null,
            "values" : [],
            "mode" : "time"
         },
         "steppedLine" : false,
         "type" : "graph",
         "percentage" : false,
         "legend" : {
            "avg" : false,
            "min" : false,
            "show" : true,
            "total" : false,
            "max" : false,
            "current" : false,
            "values" : false
         },
         "points" : false,
         "links" : [],
         "lines" : true,
         "linewidth" : 2,
         "yaxes" : [
            {
               "show" : true,
               "min" : null,
               "label" : null,
               "logBase" : 1,
               "format" : "short",
               "max" : null
            },
            {
               "max" : null,
               "format" : "short",
               "logBase" : 1,
               "label" : null,
               "min" : null,
               "show" : true
            }
         ],
         "renderer" : "flot",
         "grid" : {},
         "title" : "Milter connections rate",
         "datasource" : "${DS_PROMETHEUS}",
         "timeFrom" : null,
         "seriesOverrides" : [],
         "stack" : false,
         "nullPointMode" : "connected",
         "id" : 37,
         "bars" : false,
         "tooltip" : {
            "shared" : true,
            "msResolution" : false,
            "sort" : 2,
            "value_type" : "cumulative"
         },
         "error" : false,
         "timeShift" : null,
         "thresholds" : [],
         "fill" : 1,
         "span" : 12,
         "editable" : true,
         "targets" : [
            {
               "step" : 4,
               "intervalFactor" : 2,
               "refId" : "A",
               "legendFormat" : "Connections",
               "expr" : "sum(rate(authmilter_connect_total{node=~\"$node\"}[$ratetime]))",
               "metric" : "authmilter_connect_total"
            }
         ]
      },
      {
         "thresholds" : [],
         "fill" : 0,
         "timeShift" : null,
         "targets" : [
            {
               "step" : 4,
               "intervalFactor" : 2,
               "interval" : "",
               "refId" : "A",
               "legendFormat" : "{{ node }}",
               "expr" : "sum(rate(authmilter_mail_processed_total{node=~\"$node\"}[$ratetime])) by(node)",
               "metric" : "authmilter_mail_"
            }
         ],
         "span" : 12,
         "editable" : true,
         "nullPointMode" : "connected",
         "id" : 17,
         "tooltip" : {
            "shared" : true,
            "msResolution" : false,
            "value_type" : "cumulative",
            "sort" : 2
         },
         "bars" : false,
         "error" : false,
         "datasource" : "${DS_PROMETHEUS}",
         "title" : "Emails processed rate by node",
         "seriesOverrides" : [],
         "stack" : false,
         "timeFrom" : null,
         "xaxis" : {
            "mode" : "time",
            "values" : [],
            "show" : true,
            "name" : null
         },
         "pointradius" : 5,
         "aliasColors" : {},
         "type" : "graph",
         "steppedLine" : false,
         "grid" : {},
         "legend" : {
            "total" : false,
            "avg" : false,
            "current" : false,
            "values" : false,
            "hideZero" : true,
            "min" : false,
            "show" : true,
            "max" : false
         },
         "points" : false,
         "lines" : true,
         "percentage" : false,
         "links" : [],
         "linewidth" : 2,
         "renderer" : "flot",
         "yaxes" : [
            {
               "min" : null,
               "show" : true,
               "logBase" : 1,
               "format" : "short",
               "max" : null,
               "label" : null
            },
            {
               "show" : true,
               "min" : null,
               "label" : null,
               "logBase" : 1,
               "format" : "short",
               "max" : null
            }
         ]
      }
   ],
   "collapse" : true,
   "repeatIteration" : null,
   "title" : "Throughput",
   "height" : "250px",
   "repeat" : null,
   "titleSize" : "h6",
   "showTitle" : true
}
';
}

sub get_RowProcesses {
    return '
{
   "height" : "250px",
   "titleSize" : "h6",
   "showTitle" : true,
   "collapse" : true,
   "title" : "Processes",
   "repeatIteration" : null,
   "panels" : [
      {
         "timeFrom" : null,
         "editable" : true,
         "aliasColors" : {},
         "title" : "Children count",
         "thresholds" : [],
         "points" : false,
         "links" : [],
         "error" : false,
         "renderer" : "flot",
         "xaxis" : {
            "mode" : "time",
            "values" : [],
            "show" : true,
            "name" : null
         },
         "steppedLine" : false,
         "stack" : true,
         "grid" : {},
         "legend" : {
            "current" : false,
            "min" : false,
            "max" : false,
            "avg" : false,
            "total" : false,
            "show" : true,
            "values" : false
         },
         "percentage" : false,
         "seriesOverrides" : [],
         "fill" : 1,
         "yaxes" : [
            {
               "format" : "short",
               "label" : null,
               "max" : null,
               "min" : 0,
               "logBase" : 1,
               "show" : true
            },
            {
               "format" : "short",
               "label" : null,
               "max" : null,
               "logBase" : 1,
               "min" : null,
               "show" : true
            }
         ],
         "targets" : [
            {
               "metric" : "authmilter_",
               "expr" : "sum(authmilter_processes_waiting{node=~\"$node\"})",
               "legendFormat" : "Spare children",
               "intervalFactor" : 2,
               "interval" : "",
               "refId" : "A",
               "step" : 4
            },
            {
               "step" : 4,
               "refId" : "B",
               "metric" : "authmilter_",
               "expr" : "sum(authmilter_processes_processing{node=~\"$node\"})",
               "intervalFactor" : 2,
               "legendFormat" : "Busy children"
            }
         ],
         "datasource" : "${DS_PROMETHEUS}",
         "type" : "graph",
         "tooltip" : {
            "sort" : 2,
            "shared" : true,
            "msResolution" : false,
            "value_type" : "individual"
         },
         "id" : 18,
         "timeShift" : null,
         "lines" : true,
         "span" : 12,
         "pointradius" : 5,
         "bars" : true,
         "nullPointMode" : "connected",
         "linewidth" : 2
      },
      {
         "editable" : true,
         "aliasColors" : {},
         "timeFrom" : null,
         "title" : "Total children by node",
         "thresholds" : [],
         "points" : false,
         "links" : [],
         "renderer" : "flot",
         "xaxis" : {
            "show" : true,
            "name" : null,
            "mode" : "time",
            "values" : []
         },
         "steppedLine" : false,
         "stack" : false,
         "error" : false,
         "legend" : {
            "avg" : false,
            "min" : false,
            "total" : false,
            "max" : false,
            "current" : false,
            "show" : true,
            "values" : false
         },
         "grid" : {},
         "percentage" : false,
         "fill" : 0,
         "seriesOverrides" : [],
         "yaxes" : [
            {
               "label" : null,
               "format" : "short",
               "min" : 0,
               "max" : null,
               "logBase" : 1,
               "show" : true
            },
            {
               "show" : true,
               "min" : null,
               "logBase" : 1,
               "max" : null,
               "label" : null,
               "format" : "short"
            }
         ],
         "datasource" : "${DS_PROMETHEUS}",
         "targets" : [
            {
               "intervalFactor" : 2,
               "legendFormat" : "{{ node }}",
               "expr" : "sum(authmilter_processes_waiting{node=~\"$node\"}+authmilter_processes_processing{node=~\"$node\"}) by(node)",
               "metric" : "authmilter_",
               "step" : 4,
               "refId" : "A",
               "interval" : ""
            }
         ],
         "type" : "graph",
         "timeShift" : null,
         "id" : 7,
         "tooltip" : {
            "value_type" : "individual",
            "msResolution" : false,
            "shared" : true,
            "sort" : 2
         },
         "pointradius" : 5,
         "lines" : true,
         "span" : 12,
         "linewidth" : 2,
         "bars" : false,
         "nullPointMode" : "connected"
      },
      {
         "title" : "Spare children by node",
         "timeFrom" : null,
         "editable" : true,
         "aliasColors" : {},
         "links" : [],
         "thresholds" : [],
         "points" : false,
         "legend" : {
            "values" : false,
            "show" : true,
            "total" : false,
            "min" : false,
            "avg" : false,
            "max" : false,
            "current" : false
         },
         "grid" : {},
         "error" : false,
         "steppedLine" : false,
         "renderer" : "flot",
         "stack" : false,
         "xaxis" : {
            "show" : true,
            "name" : null,
            "mode" : "time",
            "values" : []
         },
         "percentage" : false,
         "seriesOverrides" : [],
         "fill" : 0,
         "type" : "graph",
         "targets" : [
            {
               "refId" : "A",
               "step" : 4,
               "interval" : "",
               "legendFormat" : "{{ node }}",
               "intervalFactor" : 2,
               "expr" : "sum(authmilter_processes_waiting{node=~\"$node\"}) by(node)",
               "metric" : "authmilter_"
            }
         ],
         "datasource" : "${DS_PROMETHEUS}",
         "yaxes" : [
            {
               "min" : 0,
               "logBase" : 1,
               "max" : null,
               "show" : true,
               "label" : null,
               "format" : "short"
            },
            {
               "label" : null,
               "format" : "short",
               "show" : true,
               "max" : null,
               "logBase" : 1,
               "min" : null
            }
         ],
         "tooltip" : {
            "sort" : 2,
            "shared" : true,
            "msResolution" : false,
            "value_type" : "individual"
         },
         "timeShift" : null,
         "id" : 19,
         "nullPointMode" : "connected",
         "bars" : false,
         "linewidth" : 2,
         "lines" : true,
         "span" : 12,
         "pointradius" : 5
      },
      {
         "links" : [],
         "points" : false,
         "thresholds" : [],
         "title" : "Processing children by node",
         "aliasColors" : {},
         "editable" : true,
         "timeFrom" : null,
         "percentage" : false,
         "legend" : {
            "total" : false,
            "min" : false,
            "max" : false,
            "avg" : false,
            "current" : false,
            "show" : true,
            "values" : false
         },
         "grid" : {},
         "renderer" : "flot",
         "steppedLine" : false,
         "stack" : false,
         "xaxis" : {
            "mode" : "time",
            "values" : [],
            "show" : true,
            "name" : null
         },
         "error" : false,
         "targets" : [
            {
               "refId" : "A",
               "step" : 4,
               "interval" : "",
               "legendFormat" : "{{ node }}",
               "intervalFactor" : 2,
               "expr" : "sum(authmilter_processes_processing{node=~\"$node\"}) by(node)",
               "metric" : "authmilter_"
            }
         ],
         "datasource" : "${DS_PROMETHEUS}",
         "type" : "graph",
         "yaxes" : [
            {
               "max" : null,
               "min" : 0,
               "logBase" : 1,
               "show" : true,
               "label" : null,
               "format" : "short"
            },
            {
               "label" : null,
               "format" : "short",
               "logBase" : 1,
               "min" : null,
               "max" : null,
               "show" : true
            }
         ],
         "fill" : 0,
         "seriesOverrides" : [],
         "linewidth" : 2,
         "bars" : false,
         "nullPointMode" : "connected",
         "span" : 12,
         "pointradius" : 5,
         "lines" : true,
         "id" : 20,
         "timeShift" : null,
         "tooltip" : {
            "value_type" : "individual",
            "msResolution" : false,
            "shared" : true,
            "sort" : 2
         }
      },
      {
         "fill" : 1,
         "seriesOverrides" : [],
         "yaxes" : [
            {
               "min" : null,
               "max" : null,
               "logBase" : 1,
               "show" : true,
               "format" : "short",
               "label" : null
            },
            {
               "label" : null,
               "format" : "short",
               "logBase" : 1,
               "max" : null,
               "min" : null,
               "show" : true
            }
         ],
         "targets" : [
            {
               "step" : 4,
               "refId" : "A",
               "intervalFactor" : 2,
               "legendFormat" : "Children forked",
               "expr" : "sum(rate(authmilter_forked_children_total{node=~\"$node\"}[$ratetime]))",
               "metric" : "authmilter_f"
            },
            {
               "interval" : "",
               "step" : 4,
               "refId" : "B",
               "expr" : "-sum(rate(authmilter_reaped_children_total{node=~\"$node\"}[$ratetime]))",
               "metric" : "authmilter_f",
               "intervalFactor" : 2,
               "legendFormat" : "Children reaped"
            },
            {
               "interval" : "",
               "refId" : "C",
               "step" : 4,
               "expr" : "sum(rate(authmilter_forked_children_total{node=~\"$node\"}[$ratetime]))-sum(rate(authmilter_reaped_children_total{node=~\"$node\"}[$ratetime]))",
               "legendFormat" : "Children churn",
               "intervalFactor" : 2
            }
         ],
         "type" : "graph",
         "datasource" : "${DS_PROMETHEUS}",
         "timeShift" : null,
         "id" : 31,
         "tooltip" : {
            "value_type" : "cumulative",
            "msResolution" : false,
            "shared" : true,
            "sort" : 2
         },
         "lines" : true,
         "pointradius" : 5,
         "span" : 12,
         "linewidth" : 2,
         "nullPointMode" : "connected",
         "bars" : false,
         "aliasColors" : {},
         "editable" : true,
         "timeFrom" : null,
         "title" : "Fork rate",
         "points" : false,
         "thresholds" : [],
         "links" : [],
         "xaxis" : {
            "name" : null,
            "show" : true,
            "values" : [],
            "mode" : "time"
         },
         "renderer" : "flot",
         "stack" : false,
         "steppedLine" : false,
         "error" : false,
         "legend" : {
            "current" : false,
            "max" : false,
            "min" : false,
            "total" : false,
            "avg" : false,
            "show" : true,
            "values" : false
         },
         "grid" : {},
         "percentage" : false
      }
   ],
   "repeat" : null,
   "repeatRowId" : null
}
';
}

sub get_RowProcessingTime {
    return '
{
   "repeat" : null,
   "title" : "Processing Time",
   "collapse" : true,
   "titleSize" : "h6",
   "repeatRowId" : null,
   "showTitle" : true,
   "panels" : [
      {
         "seriesOverrides" : [],
         "steppedLine" : false,
         "nullPointMode" : "connected",
         "error" : false,
         "points" : false,
         "editable" : true,
         "linewidth" : 2,
         "tooltip" : {
            "shared" : true,
            "sort" : 2,
            "msResolution" : false,
            "value_type" : "cumulative"
         },
         "lines" : true,
         "timeFrom" : null,
         "percentage" : false,
         "datasource" : "${DS_PROMETHEUS}",
         "fill" : 1,
         "legend" : {
            "max" : false,
            "show" : true,
            "min" : false,
            "avg" : false,
            "values" : false,
            "total" : false,
            "current" : false
         },
         "title" : "Processing Time",
         "span" : 12,
         "timeShift" : null,
         "id" : 36,
         "renderer" : "flot",
         "type" : "graph",
         "pointradius" : 5,
         "targets" : [
            {
               "legendFormat" : "Time",
               "expr" : "sum(rate(authmilter_time_microseconds_total{node=~\"$node\"}[$ratetime]))",
               "refId" : "A",
               "intervalFactor" : 2,
               "metric" : "authmilter_f",
               "step" : 4,
               "interval" : ""
            }
         ],
         "xaxis" : {
            "show" : true,
            "values" : [],
            "mode" : "time",
            "name" : null
         },
         "links" : [],
         "bars" : false,
         "thresholds" : [],
         "grid" : {},
         "aliasColors" : {},
         "yaxes" : [
            {
               "label" : null,
               "logBase" : 1,
               "format" : "µs",
               "show" : true,
               "min" : null,
               "max" : null
            },
            {
               "label" : null,
               "logBase" : 1,
               "format" : "short",
               "min" : null,
               "show" : true,
               "max" : null
            }
         ],
         "stack" : false
      },
      {
         "title" : "Time per Handler",
         "fill" : 1,
         "legend" : {
            "current" : false,
            "total" : false,
            "max" : false,
            "avg" : false,
            "values" : false,
            "show" : true,
            "min" : false
         },
         "span" : 12,
         "percentage" : false,
         "datasource" : "${DS_PROMETHEUS}",
         "lines" : true,
         "timeFrom" : null,
         "tooltip" : {
            "sort" : 2,
            "shared" : true,
            "msResolution" : false,
            "value_type" : "cumulative"
         },
         "editable" : true,
         "linewidth" : 2,
         "error" : false,
         "nullPointMode" : "connected",
         "points" : false,
         "seriesOverrides" : [],
         "steppedLine" : false,
         "aliasColors" : {},
         "grid" : {},
         "yaxes" : [
            {
               "label" : null,
               "logBase" : 1,
               "format" : "µs",
               "max" : null,
               "min" : null,
               "show" : true
            },
            {
               "show" : true,
               "min" : null,
               "max" : null,
               "label" : null,
               "logBase" : 1,
               "format" : "short"
            }
         ],
         "thresholds" : [],
         "stack" : false,
         "links" : [],
         "xaxis" : {
            "values" : [],
            "show" : true,
            "mode" : "time",
            "name" : null
         },
         "bars" : false,
         "targets" : [
            {
               "legendFormat" : "{{ handler }}",
               "expr" : "sum(rate(authmilter_time_microseconds_total{node=~\"$node\"}[$ratetime])) by(handler)",
               "intervalFactor" : 2,
               "refId" : "A",
               "metric" : "authmilter_f",
               "step" : 4,
               "interval" : ""
            }
         ],
         "pointradius" : 5,
         "id" : 32,
         "renderer" : "flot",
         "type" : "graph",
         "timeShift" : null
      },
      {
         "datasource" : "${DS_PROMETHEUS}",
         "percentage" : false,
         "timeFrom" : null,
         "lines" : true,
         "legend" : {
            "current" : false,
            "total" : false,
            "max" : false,
            "avg" : false,
            "values" : false,
            "min" : false,
            "show" : true
         },
         "span" : 12,
         "fill" : 1,
         "title" : "Time per Callback",
         "points" : false,
         "error" : false,
         "nullPointMode" : "connected",
         "seriesOverrides" : [],
         "steppedLine" : false,
         "tooltip" : {
            "msResolution" : false,
            "value_type" : "cumulative",
            "sort" : 2,
            "shared" : true
         },
         "linewidth" : 2,
         "editable" : true,
         "targets" : [
            {
               "metric" : "authmilter_f",
               "step" : 4,
               "interval" : "",
               "expr" : "sum(rate(authmilter_time_microseconds_total{node=~\"$node\"}[$ratetime])) by(callback)",
               "legendFormat" : "{{ callback }}",
               "refId" : "A",
               "intervalFactor" : 2
            }
         ],
         "pointradius" : 5,
         "stack" : false,
         "thresholds" : [],
         "aliasColors" : {},
         "grid" : {},
         "yaxes" : [
            {
               "min" : null,
               "show" : true,
               "max" : null,
               "logBase" : 1,
               "format" : "µs",
               "label" : null
            },
            {
               "min" : null,
               "show" : true,
               "max" : null,
               "format" : "short",
               "logBase" : 1,
               "label" : null
            }
         ],
         "bars" : false,
         "links" : [],
         "xaxis" : {
            "name" : null,
            "mode" : "time",
            "show" : true,
            "values" : []
         },
         "timeShift" : null,
         "type" : "graph",
         "renderer" : "flot",
         "id" : 33
      },
      {
         "timeShift" : null,
         "type" : "graph",
         "id" : 34,
         "renderer" : "flot",
         "targets" : [
            {
               "metric" : "authmilter_f",
               "step" : 4,
               "interval" : "",
               "expr" : "sum(rate(authmilter_time_microseconds_total{node=~\"$node\"}[$ratetime])) by(callback,handler)",
               "legendFormat" : "{{ callback }} {{ handler }}",
               "intervalFactor" : 2,
               "refId" : "A"
            }
         ],
         "pointradius" : 5,
         "stack" : false,
         "yaxes" : [
            {
               "format" : "µs",
               "logBase" : 1,
               "label" : null,
               "min" : null,
               "show" : true,
               "max" : null
            },
            {
               "label" : null,
               "format" : "short",
               "logBase" : 1,
               "max" : null,
               "show" : true,
               "min" : null
            }
         ],
         "thresholds" : [],
         "aliasColors" : {},
         "grid" : {},
         "bars" : false,
         "xaxis" : {
            "show" : true,
            "values" : [],
            "mode" : "time",
            "name" : null
         },
         "links" : [],
         "points" : false,
         "error" : false,
         "nullPointMode" : "connected",
         "seriesOverrides" : [],
         "steppedLine" : false,
         "tooltip" : {
            "msResolution" : false,
            "value_type" : "cumulative",
            "shared" : true,
            "sort" : 2
         },
         "linewidth" : 2,
         "editable" : true,
         "datasource" : "${DS_PROMETHEUS}",
         "percentage" : false,
         "timeFrom" : null,
         "lines" : true,
         "legend" : {
            "avg" : false,
            "values" : false,
            "show" : true,
            "min" : false,
            "max" : false,
            "current" : false,
            "total" : false
         },
         "span" : 12,
         "title" : "Time per Callback/Handler",
         "fill" : 1
      }
   ],
   "height" : 250,
   "repeatIteration" : null
}
';
}

sub get_RowErrors {
    return '
{
   "showTitle" : true,
   "repeat" : null,
   "collapse" : true,
   "titleSize" : "h6",
   "title" : "Errors",
   "repeatIteration" : null,
   "repeatRowId" : null,
   "height" : "250px",
   "panels" : [
      {
         "id" : 10,
         "linewidth" : 2,
         "aliasColors" : {},
         "timeShift" : null,
         "type" : "graph",
         "xaxis" : {
            "values" : [],
            "name" : null,
            "mode" : "time",
            "show" : true
         },
         "datasource" : "${DS_PROMETHEUS}",
         "editable" : true,
         "fill" : 1,
         "grid" : {},
         "span" : 12,
         "bars" : false,
         "renderer" : "flot",
         "stack" : false,
         "title" : "Callback Errors Total",
         "links" : [],
         "tooltip" : {
            "msResolution" : false,
            "value_type" : "cumulative",
            "sort" : 2,
            "shared" : true
         },
         "targets" : [
            {
               "metric" : "authmilter_call",
               "refId" : "A",
               "interval" : "",
               "intervalFactor" : 2,
               "step" : 4,
               "expr" : "sum(authmilter_callback_error_total{node=~\"$node\"}) by(stage)",
               "legendFormat" : "{{ stage }}"
            }
         ],
         "lines" : true,
         "timeFrom" : null,
         "yaxes" : [
            {
               "logBase" : 1,
               "format" : "short",
               "show" : true,
               "max" : null,
               "label" : null,
               "min" : null
            },
            {
               "format" : "short",
               "logBase" : 1,
               "show" : true,
               "label" : null,
               "max" : null,
               "min" : null
            }
         ],
         "seriesOverrides" : [],
         "percentage" : false,
         "nullPointMode" : "connected",
         "error" : false,
         "points" : false,
         "legend" : {
            "avg" : false,
            "values" : false,
            "current" : false,
            "min" : false,
            "max" : false,
            "show" : true,
            "hideZero" : true,
            "total" : false
         },
         "steppedLine" : false,
         "thresholds" : [],
         "pointradius" : 5
      }
   ]
}
';
}

sub get_RowUptime {
    return '
{
   "repeatRowId" : null,
   "repeat" : null,
   "panels" : [
      {
         "type" : "graph",
         "grid" : {},
         "stack" : false,
         "span" : 12,
         "timeShift" : null,
         "lines" : true,
         "datasource" : "${DS_PROMETHEUS}",
         "steppedLine" : false,
         "id" : 11,
         "fill" : 0,
         "aliasColors" : {},
         "seriesOverrides" : [],
         "title" : "Uptime",
         "renderer" : "flot",
         "linewidth" : 2,
         "links" : [],
         "pointradius" : 5,
         "nullPointMode" : "connected",
         "editable" : true,
         "error" : false,
         "yaxes" : [
            {
               "logBase" : 1,
               "format" : "s",
               "show" : true,
               "max" : null,
               "min" : null,
               "label" : ""
            },
            {
               "format" : "short",
               "logBase" : 1,
               "show" : true,
               "min" : null,
               "max" : null,
               "label" : null
            }
         ],
         "legend" : {
            "current" : false,
            "show" : true,
            "total" : false,
            "max" : false,
            "min" : false,
            "avg" : false,
            "values" : false
         },
         "bars" : false,
         "percentage" : false,
         "tooltip" : {
            "sort" : 2,
            "value_type" : "cumulative",
            "shared" : true,
            "msResolution" : false
         },
         "timeFrom" : null,
         "thresholds" : [],
         "targets" : [
            {
               "intervalFactor" : 2,
               "refId" : "A",
               "expr" : "sum(authmilter_uptime_seconds_total{node=~\"$node\"}) by(node)",
               "legendFormat" : "Uptime {{ node }}",
               "step" : 4
            }
         ],
         "xaxis" : {
            "mode" : "time",
            "values" : [],
            "name" : null,
            "show" : true
         },
         "points" : false
      }
   ],
   "titleSize" : "h6",
   "height" : "250px",
   "repeatIteration" : null,
   "collapse" : true,
   "showTitle" : true,
   "title" : "Uptime"
}
';
}

#####

sub new {
    my ( $class ) = @_;
    my $self = {};
    bless $self, $class;
    return $self;
}

sub get_dashboard {
    my ( $self, $server ) = @_;

    my @Rows;
    # Add default system rows
    push @Rows, $self->get_RowThroughput();
    push @Rows, $self->get_RowProcesses();
    push @Rows, $self->get_RowProcessingTime();
    push @Rows, $self->get_RowErrors();
    push @Rows, $self->get_RowUptime;

    foreach my $Handler ( sort keys %{ $server->{ 'handler' } } ) {
        my $HandlerObj = $server->{ 'handler' }->{ $Handler };
        if ( $HandlerObj->can( 'grafana_rows' ) ) {
            my $HandlerRows = $HandlerObj->grafana_rows();
            foreach my $Row ( @$HandlerRows ) {
                push @Rows, $Row if $Row;
            }
        }
    }

    my $J = JSON->new();
    $J->pretty();

    my $Base = $self->get_Base();
    my $BaseData = $J->decode( $Base );
    my $RowsData = $J->decode( '[' . join( ',', @Rows ) . ']' );
    $BaseData->{ 'rows' } = $RowsData;
    return $J->encode( $BaseData ) . "\n";
}

1;

__END__

=head1 NAME

Mail::Milter::Authentication::Metric::Grafana - Automatically generate Grafana dashboard

=head1 DESCRIPTION

Automatically generate a grafana dashboard for installed handlers

=head1 CONSTRUCTOR

=over

=item new()

my $object = Mail::Milter::Authentication::Metric::Grafana->new();

Creates a new object.

=back

=head1 METHODS

=over

=item get_Base()

Returns the base json for the dashboard

=item get_RowThroughput()

Returns the Row json for THroughput

=item get_RowProcesses()

Returns the Row json for Processes

=item get_RowProcessingTime()

Returns the Row json for Processing TIme

=item get_RowErrors()

Returns the Row json for Errors

=item get_RowUptime()

Returns the Row json for Uptime

=item get_dashboard( $server )

Returns the json for the grafana dashboard

$server is the current handler object

=back

=head1 AUTHORS

Marc Bradshaw E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT

Copyright 2017

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

