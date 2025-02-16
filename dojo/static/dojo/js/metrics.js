/*
        dashboard.html
*/

function homepage_pie_chart(critical, high, medium, low, info) {
    var data = [{
        label: "Critical",
        color: "#d9534f",
        data: critical
    }, {
        label: "High",
        color: "#f0ad4e",
        data: high
    }, {
        label: "Medium",
        color: "#f0de28",
        data: medium
    }, {
        label: "Low",
        color: "#337ab7",
        data: low
    }, {
        label: "Informational",
        color: "#E0E0E0",
        data: info
    }];

    var plotObj = $.plot($("#homepage_pie_chart"), data, {
        series: {
            pie: {
                innerRadius: 0.5,
                show: true,
                radius: 1,
                label: {
                    show: false,
                    radius: 2 / 3,
                    formatter: function (label, series) {
                        return '<div style="font-size:8pt;text-align:center;padding:2px;color:black;z-index:9999;">' + label + '<br/>' + series.data[0][1] + '</div>';

                    },

                }
            }
        },
        grid: {
            hoverable: true,
        },
        tooltip:true,
        tooltipOpts: {
            content: function(label, xval, yval, flotItem) {
                return label+"<br>"+yval
            }
        }
    });
}

function homepage_severity_plot(critical, high, medium, low) {
    var options = {
        xaxes: [{
            mode: 'time',
            minTickSize: [1, "month"]
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7',
    
        },
        tooltip: true,
    };

    var plotObj = $.plot($("#homepage_severity_plot"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
}

/*
        dashboard-metrics.html
*/

function getTicks(critical, high, medium, low) {
    return [...new Set(critical.concat(high, medium, low).map(x => x[0]))]
}

function opened_per_month(critical, high, medium, low) {
    var options = {
        xaxes: [{
            mode: 'time',
            timeformat: "%m/%y",
            ticks: getTicks(critical, high, medium, low),
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',
    
        },
        tooltip: false,
    };

    $.plot($("#opened_per_month"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
};

function accepted_per_month(critical, high, medium, low) {
    var options = {
        xaxes: [{
            mode: 'time',
            timeformat: "%m/%y",
            ticks: getTicks(critical, high, medium, low),
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',
    
        },
        tooltip: false,
    };
    
    $.plot($("#accepted_per_month"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
};

function opened_per_week(critical, high, medium, low) {
    var options = {
        xaxes: [{
            mode: 'time',
            timeformat: "%m/%d/%Y",
            ticks: getTicks(critical, high, medium, low),
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: true,
    };

    var plotObj = $.plot($("#opened_per_week"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
}

function accepted_per_week(critical, high, medium, low) {
    var options = {
        xaxes: [{
            mode: 'time',
            timeformat: "%m/%d/%Y",
            ticks: getTicks(critical, high, medium, low),
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
    };

    var plotObj = $.plot($("#accepted_per_week"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
}

function top_ten_products(critical, high, medium, low, ticks) {
    data1 = [
        {
            data: critical,
            color: "#d9534f",
            bars: {fill: 1},
            label: 'Critical',
        },
        {
            data: high,
            color: "#f0ad4e",
            bars: {fill: 1},
            label: 'High',

        },
        {
            data: medium,
            color: "#f0de28",
            bars: {fill: 1},
            label: 'Medium',
        },
        {
            data: low,
            color: "#337ab7",
            bars: {fill: 1},
            label: 'Low',
        },
    ];

    $.plot("#top-ten", data1, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },
    });
}

function severity_pie(critical, high, medium, low) {
    var data = [{
        label: "Critical",
        color: "#d9534f",
        data: critical
    }, {
        label: "High",
        color: "#f0ad4e",
        data: high
    }, {
        label: "Medium",
        color: "#f0de28",
        data: medium
    }, {
        label: "Low",
        color: "#337ab7",
        data: low
    }];

    var plotObj = $.plot($("#opened_in_period"), data, {
        series: {
            pie: {
                show: true,
                radius: 1,
                label: {
                    show: true,
                    radius: 2 / 3,
                    formatter: function (label, series) {
                        return '<div style="font-size:8pt;text-align:center;padding:2px;color:black;z-index:9999;">' + label + '<br/>' + series.data[0][1] + '</div>';

                    },

                }
            }
        },
        grid: {
            hoverable: false
        },
    });
}

function total_accepted_pie(critical, high, medium, low) {
    var data = [{
        label: "Critical",
        color: "#d9534f",
        data: critical
    }, {
        label: "High",
        color: "#f0ad4e",
        data: high
    }, {
        label: "Medium",
        color: "#f0de28",
        data: medium
    }, {
        label: "Low",
        color: "#337ab7",
        data: low
    }];

    var plotObj = $.plot($("#total_accepted_in_period"), data, {
        series: {
            pie: {
                show: true,
                radius: 1,
                label: {
                    show: true,
                    radius: 2 / 3,
                    formatter: function (label, series) {
                        return '<div style="font-size:8pt;text-align:center;padding:2px;color:black;z-index:9999;">' + label + '<br/>' + series.data[0][1] + '</div>';

                    },

                }
            }
        },
        grid: {
            hoverable: false
        },
    });
}

function total_closed_pie(critical, high, medium, low) {
    var data = [{
        label: "Critical",
        color: "#d9534f",
        data: critical
    }, {
        label: "High",
        color: "#f0ad4e",
        data: high
    }, {
        label: "Medium",
        color: "#f0de28",
        data: medium
    }, {
        label: "Low",
        color: "#337ab7",
        data: low
    }];

    var plotObj = $.plot($("#total_closed_in_period"), data, {
        series: {
            pie: {
                show: true,
                radius: 1,
                label: {
                    show: true,
                    radius: 2 / 3,
                    formatter: function (label, series) {
                        return '<div style="font-size:8pt;text-align:center;padding:2px;color:black;z-index:9999;">' + label + '<br/>' + series.data[0][1] + '</div>';

                    },

                }
            }
        },
        grid: {
            hoverable: false
        },
    });
}

/*
        metrics.html
*/

function opened_per_month_2(critical, high, medium, low) {
    var tick_count = critical.length < 7 ? critical.length : 7;
    var options = {
        xaxis: {
            mode: "time",
            timeformat: "%m-%d-%Y",
            timezone: 'browser'
        },
        xaxes: [{
            ticks: tick_count
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7'

        },
        tooltip: true
    };
    var plotObj = $.plot($("#opened_per_month_2"), [{
            data: critical,
            label: " Critical",
            color: "#d9534f",

        }, {
            data: high,
            label: " High",
            color: '#f0ad4e',

        }, {
            data: medium,
            label: " Medium",
            color: '#f0de28',

        }, {
            data: low,
            label: " Low",
            color: '#337ab7',

        }],
        options);
}

function active_per_month(critical, high, medium, low) {
    var tick_count = critical.length < 7 ? critical.length : 7;
    var options = {
        xaxis: {
            mode: "time",
            timeformat: "%m-%d-%Y",
            timezone: 'browser'
        },
        xaxes: [{
            ticks: tick_count
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7'

        },
        tooltip: true
    };
    var plotObj = $.plot($("#active_per_month"), [{
            data: critical,
            label: " Critical",
            color: "#d9534f",

        }, {
            data: high,
            label: " High",
            color: '#f0ad4e',

        }, {
            data: medium,
            label: " Medium",
            color: '#f0de28',

        }, {
            data: low,
            label: " Low",
            color: '#337ab7',

        }],
        options);
}

function accepted_per_month_2(critical, high, medium, low) {
    var tick_count = critical.length < 7 ? critical.length : 7;
    var options = {
        xaxis: {
            mode: "time",
            timeformat: "%m-%d-%Y",
            timezone: 'browser'
        },
        xaxes: [{
            ticks: tick_count
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7'

        },
        tooltip: true
    };
    var plotObj = $.plot($("#accepted_per_month_2"), [{
            data: critical,
            label: " Critical",
            color: "#d9534f"
        }, {
            data: high,
            label: " High",
            color: '#f0ad4e'
        }, {
            data: medium,
            label: " Medium",
            color: '#f0de28'
        }, {
            data: low,
            label: " Low",
            color: '#337ab7'
        }],
        options);
}

function opened_per_week_2(critical, high, medium, low) {
    var options = {
        xaxis: {
            mode: "time",
            timeformat: "%m-%d-%Y",
            timezone: 'browser'
        },
        xaxes: [{
            ticks: 7
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7'

        },
        tooltip: true
    };


    var plotObj = $.plot($("#opened_per_week_2"), [{
            data: critical,
            label: " Critical",
            color: "#d9534f"
        }, {
            data: high,
            label: " High",
            color: '#f0ad4e'
        }, {
            data: medium,
            label: " Medium",
            color: '#f0de28'
        }, {
            data: low,
            label: " Low",
            color: '#337ab7'
        }],
        options);
}

function accepted_per_week_2(critical, high, medium, low) {
    var options = {
        xaxis: {
            mode: "time",
            timeformat: "%m-%d-%Y",
            timezone: 'browser'
        },
        xaxes: [{
            ticks: 7
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7'

        },
        tooltip: true
    };


    var plotObj = $.plot($("#accepted_per_week_2"), [{
            data: critical,
            label: " Critical",
            color: "#d9534f"
        }, {
            data: high,
            label: " High",
            color: '#f0ad4e'
        }, {
            data: medium,
            label: " Medium",
            color: '#f0de28'
        }, {
            data: low,
            label: " Low",
            color: '#337ab7'
        }],
        options);
}


// This function is valid besides metrics.html also for the dashboard-metrics.html, 
// dashboard.html, and product-metrics.html
function updatePunchcardTable(punchcardData, ticks) {
    let tableBody = $("#punchcard-table tbody");

    const daysMap = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    let formattedData = {};
    
    // No table processing in case of no data
    if (punchcardData.length === 0 || ticks.length === 0) return; 

    // Removing html elements from the ticks dates
    let ticksMap = {};
    ticks.forEach(entry => {
        let weekIndex = String(entry[0]);
        let rawHtml = entry[1]; 

        // Goodbye <span> + space instead of <br/> 
        let cleanDate = rawHtml.replace(/<\/?span[^>]*>/g, "").replace(/<br\s*\/?>/g, " ");
        cleanDate = cleanDate.trim();
        ticksMap[weekIndex] = cleanDate;
    });

    let minWeekOffset = ticks[0][0]; 
    let maxWeekOffset = ticks[ticks.length - 1][0]; 
    
    for (let weekOffset = minWeekOffset; weekOffset <= maxWeekOffset; weekOffset++) {
        let formattedDate = ticksMap[String(weekOffset)] || "Unknown Date";
        let formattedWeek = `Week ${weekOffset - minWeekOffset + 1}, starting on ${formattedDate}`;

        formattedData[formattedWeek] = {
            "Monday": 0, "Tuesday": 0, "Wednesday": 0,
            "Thursday": 0, "Friday": 0, "Saturday": 0, "Sunday": 0
        };
    }

    // Populating week data
    punchcardData.forEach(entry => {
        let weekOffset = entry[0]; 
        let day = daysMap[entry[1]];
        let value = entry[3] || 0;

        let formattedDate = ticksMap[String(weekOffset)] || "Unknown Date";
        let formattedWeek = `Week ${weekOffset - minWeekOffset + 1}, starting on ${formattedDate}`;

        if (formattedData[formattedWeek]) {
            formattedData[formattedWeek][day] = value;
        }
    });

    // Rendering accessibility table body
    Object.entries(formattedData).forEach(([week, values]) => {
        let newRow = `
            <tr>
                <td scope="row">${week}</td>
                <td>${values.Monday || '0'}</td>
                <td>${values.Tuesday || '0'}</td>
                <td>${values.Wednesday || '0'}</td>
                <td>${values.Thursday || '0'}</td>
                <td>${values.Friday || '0'}</td>
                <td>${values.Saturday || '0'}</td>
                <td>${values.Sunday || '0'}</td>
            </tr>
        `;
        tableBody.append(newRow);
    });
}

/*
        product_metrics.html
*/

function open_findings_burndown(critical, high, medium, low, info, y_max, y_min) {
    var options = {
        xaxes: [{
            mode: "time",
            timeformat: "%Y/%m/%d"
        }],
        yaxes: [{
            max: y_max,
            min: y_min
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true,
                radius: 1
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7',
    
        },
        legend: {
            position: 'nw'
        },
        tooltip: true,
    };

    var plotObj = $.plot($("#open_findings_burndown"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#4cae4c',
            }, {
                data: info,
                label: " Info",
                color: '#337ab7',
            }],
            options);
}

function accepted_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#accepted_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

function inactive_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#inactive_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

function open_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#open_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

function false_positive_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#false_positive_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

function verified_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#verified_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },
    });
}

function out_of_scope_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#out_of_scope_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },
    });
}

function all_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#all_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

function closed_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#closed_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

function new_objs(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#new_objs", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

function open_close_weekly(opened, closed, accepted, ticks) {
    var options = {
        xaxes: [{
            ticks: ticks,
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7'

        },
        tooltip: true
    };

    var plotObj = $.plot($("#open_close_weekly"), [{
                data: opened,
                label: " Opened",
                color: "#d9534f"
            }, {
                data: closed,
                label: " Closed",
                color: '#f0ad4e'
            }, {
                data: accepted,
                label: " Accepted",
                color: '#80699B'
            }],
            options);
}

function severity_weekly(critical, high, medium, low, info, ticks) {
    var options = {
        xaxes: [{
            ticks: ticks,
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7'

        },
        tooltip: true
    };

    var plotObj = $.plot($("#severity_weekly"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f"
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e'
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28'
            }, {
                data: low,
                label: " Low",
                color: '#337ab7'
            }, {
                data: info,
                label: " Info",
                color: '#80699B'
            }],
            options);

}

function severity_counts_weekly(critical, high, medium, ticks) {
    var options = {
        xaxes: [{
            ticks: ticks,
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: true,
            borderWidth: 1,
            borderColor: '#e7e7e7'

        },
        tooltip: true
    };

    var plotObj = $.plot($("#severity_critical"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f"
            }],
            options);
    var plotObj = $.plot($("#severity_high"), [{
                data: high,
                label: " High",
                color: "#f0ad4e"
            }],
            options);
    var plotObj = $.plot($("#severity_medium"), [{
                data: medium,
                label: " Medium",
                color: "#f0de28"
            }],
            options);
}

function test_type(data) {
    $.plot('#test_type', [data], {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .7,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            mode: "categories",
            tickLength: 4
        },

    });
}

function draw_vulnerabilities_graph(tag, data) {
    $.plot(tag, [data], {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .7,
                'align': "center"
            }
        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7'
        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            mode: "categories",
            tickLength: 4
        }
    });
}

/*
        view_endpoint.html
*/

/*
        view_engineer.html
*/

function open_bug_count_by_month(critical, high, medium, low, ticks) {
    var options = {
        xaxis: {
            tickFormatter: function (x) {
                return ticks[x - 1];
            },
        },
        xaxes: [{
            ticks: ticks.length,
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
    };
    var plotObj = $.plot($("#chart_div"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
}

function accepted_bug_count_by_month(critical, high, medium, low, ticks) {
    var options = {
        xaxis: {
            tickFormatter: function (x) {
                return ticks[x - 1];
            },
        },
        xaxes: [{
            ticks: ticks.length,
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
    };
    var plotObj = $.plot($("#chart_div2"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
}

function open_bug_count_by_week(critical, high, medium, low, ticks) {
    var options = {
        xaxis: {
            tickFormatter: function (x) {
                return ticks[x - 1];
            },
        },
        xaxes: [{
            ticks: ticks.length,
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
    };


    var plotObj = $.plot($("#chart_div3"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
}

function accepted_bug_count_by_week(critical, high, medium, low, ticks) {
    var options = {
        xaxis: {
            tickFormatter: function (x) {
                return ticks[x - 1];
            },
        },
        xaxes: [{
            ticks: ticks.length,
        }],
        yaxes: [{
            min: 0
        }],
        series: {
            lines: {
                show: true
            },
            points: {
                show: true
            }
        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
    };


    var plotObj = $.plot($("#chart_div4"), [{
                data: critical,
                label: " Critical",
                color: "#d9534f",
            }, {
                data: high,
                label: " High",
                color: '#f0ad4e',
            }, {
                data: medium,
                label: " Medium",
                color: '#f0de28',
            }, {
                data: low,
                label: " Low",
                color: '#337ab7',
            }],
            options);
}

/*
        view_product_details.html
*/

function languages_pie(data) {
    var plotObj = $.plot($("#donut-lang"), data, {
        series: {
            pie: {
                innerRadius: 0.5,
                show: true,
                radius: 1,
            }
        },
        legend: {
            show: true,
            container: "#donut-lang-container",
        },
        grid: {
            hoverable: true,
        }
    });
}

/*
        endpoint_pdf_report.html
*/

/*
        engagement_pdf_report.html
*/

/*
        finding_pdf_report.html
*/

/*
        product_endpoint_pdf_report.html
*/

function accepted_findings(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#accepted_findings", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

/*
        product_pdf_report.html
*/

/*
        product_type_pdf_report.html
*/

function finding_age(data_1, ticks) {
    var dataset = [
        {data: data_1, color: "#337ab7", fillColor: "#337ab7"}
    ];

    var options = {
        series: {
            bars: {
                show: true,
                fill: true,
                fillColor: "#337ab7"
            }
        },
        bars: {
            align: "center",
            barWidth: 0.5
        },
        xaxis: {
            axisLabel: "Days Open",
            axisLabelUseCanvas: true,
            axisLabelFontSizePixels: 12,
            axisLabelFontFamily: 'Verdana, Arial',
            axisLabelPadding: 10,
            ticks: ticks,
        },
        yaxis: {
            axisLabel: "Number of Findings",
            axisLabelUseCanvas: true,
            axisLabelFontSizePixels: 12,
            axisLabelFontFamily: 'Verdana, Arial',
            axisLabelPadding: 3,
        },
        legend: {
            show: false,
        },
        grid: {
            borderWidth: 1,
            borderColor: '#e7e7e7',
        }
    };

    $.plot("#finding_age", dataset, options);
}

function open_findings(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#open_findings", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

function closed_findings(d1, d2, d3, d4, d5, ticks) {
    var data = [
        {
            label: "Critical",
            data: d1,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 1,
                fillColor: "#d9534f"
            },
            color: "#d9534f"
        },
        {
            label: "High",
            data: d2,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 2,
                fillColor: "#f0ad4e"
            },
            color: "#f0ad4e"
        },
        {
            label: "Medium",
            data: d3,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 3,
                fillColor: "#f0de28"
            },
            color: "#f0de28"
        },
        {
            label: "Low",
            data: d4,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#337ab7"
            },
            color: "#337ab7"
        },
        {
            label: "info",
            data: d5,
            bars: {
                show: true,
                fill: true,
                lineWidth: 1,
                order: 4,
                fillColor: "#80699B"
            },
            color: "#80699B"
        }
    ];

    $.plot("#closed_findings", data, {
        series: {
            stack: true,
            bars: {
                show: true,
                barWidth: .9,
                'align': "center",
            },

        },
        grid: {
            hoverable: false,
            borderWidth: 1,
            borderColor: '#e7e7e7',

        },
        tooltip: false,
        legend: {
            show: false,
            position: "ne"
        },
        xaxis: {
            ticks: ticks,
        },

    });
}

/*
        test_pdf_report.html
*/