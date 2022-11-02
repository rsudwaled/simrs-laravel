@extends('adminlte::page')

@section('title', 'Laporan Antrian')

@section('content_header')
    <h1>Laporan Antrian</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Filter Data Antrian" theme="secondary" collapsible>
                <form action="{{ route('antrian.laporan') }}" method="get">
                    <div class="row">
                        <div class="col-md-3">
                            @php
                                $config = [
                                    'locale' => ['format' => 'YYYY/MM/DD'],
                                ];
                            @endphp
                            <x-adminlte-date-range name="tanggal" label="Periode Tanggal Antrian"
                                enable-default-ranges="Today" :config="$config">
                                <x-slot name="prependSlot">
                                    <div class="input-group-text bg-primary">
                                        <i class="fas fa-calendar-alt"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-date-range>
                        </div>
                    </div>
                    <x-adminlte-button type="submit" class="withLoad" theme="primary" label="Submit Antrian" />
                </form>
            </x-adminlte-card>
            <div class="row">
                <div class="col-md-3">
                    <x-adminlte-small-box title="{{ $antrians->count() }}" text="Total Antrian Terdaftar" theme="success"
                        icon="fas fa-users" />
                </div>
                <div class="col-md-3">
                    <x-adminlte-small-box title="{{ $kunjungans->count() }}" text="Total Kunjungan Pasien" theme="warning"
                        icon="fas fa-users" />
                </div>
                <div class="col-md-3">
                    <x-adminlte-small-box
                        title="{{ $antrians->count() == 0 || $kunjungans->count() == 0 ? 0 : round(($antrians->count() / $kunjungans->count()) * 100) }} % "
                        text="Persentase Pemutakhir Data" theme="primary" icon="fas fa-users" />
                </div>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <x-adminlte-card title="Grafik Jenis Pasien Poliklinik" theme="primary" icon="fas fa-info-circle"
                        collapsible>
                        <canvas id="donutChartJenisPasien"
                            style="min-height: 300px; height: 300px; max-height: 300px; max-width: 100%;"></canvas>
                        <br>
                        <ul style="list-style-type:disc;">
                            <li>Data diambil dari database Kunjungan Pasien SIMRS</li>
                            <li>Data Pasien JKN diambil dari kunjungan yang mempunyai SEP</li>
                            <li>Data Pasien NON-JKN diambil dari kunjungan yang TIDAK mempunyai SEP</li>
                            <li>Total Kunjungan : {{ $kunjungans->count() }} </li>
                        </ul>
                    </x-adminlte-card>
                </div>
                <div class="col-md-4">
                    <x-adminlte-card title="Grafik Metode Antrian Poliklinik" theme="primary" icon="fas fa-info-circle"
                        collapsible>
                        <canvas id="donutChartMethod"
                            style="min-height: 300px; height: 300px; max-height: 300px; max-width: 100%;"></canvas>
                        <br>
                        <ul style="list-style-type:disc;">
                            <li>Data diambil dari database Antrian SIMRS</li>
                            <li>Total Antrian : {{ $antrians->count() }} </li>
                        </ul>
                    </x-adminlte-card>
                </div>
                <div class="col-md-4">
                    <x-adminlte-card title="Grafik Taskid Antrian Poliklinik" theme="primary" icon="fas fa-info-circle"
                        collapsible>
                        <canvas id="donutChartTaskid"
                            style="min-height: 300px; height: 300px; max-height: 300px; max-width: 100%;"></canvas>
                        <br>
                        <ul style="list-style-type:disc;">
                            <li>Taskid adalah tahapan antrian rawat jalan</li>
                            <li>Data diambil dari database Antrian SIMRS</li>
                            <li>Total Antrian : {{ $antrians->count() }} </li>
                        </ul>
                    </x-adminlte-card>
                </div>
                <div class="col-md-6">
                    <!-- LINE CHART -->
                    {{-- <div class="card card-info">
                        <div class="card-header">
                            <h3 class="card-title">Line Chart</h3>

                            <div class="card-tools">
                                <button type="button" class="btn btn-tool" data-card-widget="collapse">
                                    <i class="fas fa-minus"></i>
                                </button>
                                <button type="button" class="btn btn-tool" data-card-widget="remove">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="chart">
                                <canvas id="lineChart"
                                    style="min-height: 250px; height: 250px; max-height: 250px; max-width: 100%;"></canvas>
                            </div>
                        </div>
                        <!-- /.card-body -->
                    </div> --}}
                    <!-- /.card -->

                    <!-- BAR CHART -->
                    {{-- <div class="card card-success">
                        <div class="card-header">
                            <h3 class="card-title">Bar Chart</h3>

                            <div class="card-tools">
                                <button type="button" class="btn btn-tool" data-card-widget="collapse">
                                    <i class="fas fa-minus"></i>
                                </button>
                                <button type="button" class="btn btn-tool" data-card-widget="remove">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="chart">
                                <canvas id="barChart"
                                    style="min-height: 250px; height: 250px; max-height: 250px; max-width: 100%;"></canvas>
                            </div>
                        </div>
                        <!-- /.card-body -->
                    </div> --}}
                    <!-- /.card -->

                    <!-- STACKED BAR CHART -->
                    {{-- <div class="card card-success">
                    <div class="card-header">
                      <h3 class="card-title">Stacked Bar Chart</h3>

                      <div class="card-tools">
                        <button type="button" class="btn btn-tool" data-card-widget="collapse">
                          <i class="fas fa-minus"></i>
                        </button>
                        <button type="button" class="btn btn-tool" data-card-widget="remove">
                          <i class="fas fa-times"></i>
                        </button>
                      </div>
                    </div>
                    <div class="card-body">
                      <div class="chart">
                        <canvas id="stackedBarChart"
                          style="min-height: 250px; height: 250px; max-height: 250px; max-width: 100%;"></canvas>
                      </div>
                    </div>
                    <!-- /.card-body -->
                  </div> --}}
                    <!-- /.card -->
                </div>
            </div>
            <x-adminlte-card title="Antrian Poliklinik" theme="primary" icon="fas fa-info-circle" collapsible>
                @if ($errors->any())
                    <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                        <ul>
                            @foreach ($errors->all() as $error)
                                <li>{{ $error }}</li>
                            @endforeach
                        </ul>
                    </x-adminlte-alert>
                @endif
                @php
                    $heads = ['Poliklinik', 'Blm. Chkin', 'Tggu. Poli', 'Poliklinik', 'S. Poli', 'Tggu. Farmasi', 'Racik', 'Selesai', 'Batal', 'Total', 'Kunjungan', '%'];
                    $config = [
                        'order' => ['2', 'desc'],
                        'paging' => false,
                        'buttons' => [
                            [
                                'extend' => 'colvis',
                                'className' => 'btn-info',
                            ],
                            [
                                'extend' => 'print',
                                'className' => 'btn-info',
                            ],
                            [
                                'extend' => 'pdf',
                                'className' => 'btn-info',
                            ],
                        ],
                    ];
                @endphp
                <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" :config="$config" striped bordered
                    hoverable compressed with-buttons>
                    @foreach ($units as $unit)
                        @isset($unit->poliklinik)
                            <tr>
                                <td>
                                    {{ $unit->KDPOLI }} - {{ $unit->nama_unit }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->where('taskid', 0)->count() }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->where('taskid', 3)->count() }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->where('taskid', 4)->count() }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->where('taskid', 5)->where('status_api', 1)->count() }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->where('taskid', 5)->where('status_api', 0)->count() }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->where('taskid', 6)->count() }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->where('taskid', 7)->count() }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->where('taskid', '>', 7)->count() }}
                                </td>
                                <td>
                                    {{ $antrians->where('kodepoli', $unit->KDPOLI)->count() }}
                                </td>
                                <td>
                                    {{ $kunjungans->where('kode_unit', $unit->kode_unit)->count() }}
                                </td>
                                <td>
                                    @if ($antrians->where('kodepoli', $unit->KDPOLI)->count() == 0 ||
                                        $kunjungans->where('kode_unit', $unit->kode_unit)->count() == 0)
                                        0
                                    @else
                                        {{ round(($antrians->where('kodepoli', $unit->KDPOLI)->count() / $kunjungans->where('kode_unit', $unit->kode_unit)->count()) * 100) }}
                                    @endif
                                    %
                                </td>
                            </tr>
                        @endisset
                    @endforeach
                    <tfoot>
                        <tr>
                            <th>Total</th>
                            <th>
                                {{ $antrians->where('taskid', 0)->count() }}
                            </th>
                            <th>{{ $antrians->where('taskid', 3)->count() }}</th>
                            <th>{{ $antrians->where('taskid', 4)->count() }}</th>
                            <th>{{ $antrians->where('taskid', 5)->where('status_api', 1)->count() }}</th>
                            <th>{{ $antrians->where('taskid', 5)->where('status_api', 0)->count() }}</th>
                            <th>{{ $antrians->where('taskid', 6)->count() }}</th>
                            <th>{{ $antrians->where('taskid', 7)->count() }}</th>
                            <th>{{ $antrians->where('taskid', '>', 7)->count() }}</th>
                            <th>{{ $antrians->count() }} </th>
                            <th>{{ $kunjungans->count() }} </th>
                            <th>{{ $antrians->count() == 0 || $kunjungans->count() == 0 ? 0 : round(($antrians->count() / $kunjungans->count()) * 100) }}
                                % </th>
                        </tr>
                    </tfoot>
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Datatables', true)
@section('plugins.DatatablesPlugins', true)
@section('plugins.TempusDominusBs4', true)
@section('plugins.DateRangePicker', true)
@section('plugins.Chartjs', true)
@section('js')
    <script>
        $(function() {
            /* ChartJS
             * -------
             * Here we will create a few charts using ChartJS
             */

            //--------------
            //- AREA CHART -
            //--------------

            // Get context with jQuery - using jQuery's .get() method.
            // var areaChartCanvas = $('#areaChart').get(0).getContext('2d')
            // var areaChartData = {
            //     labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
            //     datasets: [{
            //             label: 'Digital Goods',
            //             backgroundColor: 'rgba(60,141,188,0.9)',
            //             borderColor: 'rgba(60,141,188,0.8)',
            //             pointRadius: false,
            //             pointColor: '#3b8bba',
            //             pointStrokeColor: 'rgba(60,141,188,1)',
            //             pointHighlightFill: '#fff',
            //             pointHighlightStroke: 'rgba(60,141,188,1)',
            //             data: [28, 48, 40, 19, 86, 27, 90]
            //         },
            //         {
            //             label: 'Electronics',
            //             backgroundColor: 'rgba(210, 214, 222, 1)',
            //             borderColor: 'rgba(210, 214, 222, 1)',
            //             pointRadius: false,
            //             pointColor: 'rgba(210, 214, 222, 1)',
            //             pointStrokeColor: '#c1c7d1',
            //             pointHighlightFill: '#fff',
            //             pointHighlightStroke: 'rgba(220,220,220,1)',
            //             data: [65, 59, 80, 81, 56, 55, 40]
            //         },
            //     ]
            // }
            // var areaChartOptions = {
            //     maintainAspectRatio: false,
            //     responsive: true,
            //     legend: {
            //         display: false
            //     },
            //     scales: {
            //         xAxes: [{
            //             gridLines: {
            //                 display: false,
            //             }
            //         }],
            //         yAxes: [{
            //             gridLines: {
            //                 display: false,
            //             }
            //         }]
            //     }
            // }
            // // This will get the first returned node in the jQuery collection.
            // new Chart(areaChartCanvas, {
            //     type: 'line',
            //     data: areaChartData,
            //     options: areaChartOptions
            // })

            //-------------
            //- LINE CHART -
            //--------------
            // var lineChartCanvas = $('#lineChart').get(0).getContext('2d')
            // var lineChartOptions = $.extend(true, {}, areaChartOptions)
            // var lineChartData = $.extend(true, {}, areaChartData)
            // lineChartData.datasets[0].fill = false;
            // lineChartData.datasets[1].fill = false;
            // lineChartOptions.datasetFill = false
            // var lineChart = new Chart(lineChartCanvas, {
            //     type: 'line',
            //     data: lineChartData,
            //     options: lineChartOptions
            // })

            //  taskid donat
            var donutOptions = {
                maintainAspectRatio: false,
                responsive: true,
            }
            var donutChartCanvasTaskid = $('#donutChartTaskid').get(0).getContext('2d')
            var donutDataTaskid = {
                labels: [
                    'Belum Checkin',
                    'Tunggu Poli',
                    'Pelayanan Poliklinik',
                    'Selesai Poliklinik',
                    'Tunggu Farmasi',
                    'Racik Obat',
                    'Selesai',
                    'Batal Antrian',
                ],
                datasets: [{
                    data: [
                        "{{ $antrians->where('taskid', 0)->count() }}",
                        "{{ $antrians->where('taskid', 3)->count() }}",
                        "{{ $antrians->where('taskid', 4)->count() }}",
                        "{{ $antrians->where('taskid', 5)->where('status_api', 1)->count() }}",
                        "{{ $antrians->where('taskid', 5)->where('status_api', 0)->count() }}",
                        "{{ $antrians->where('taskid', 6)->count() }}",
                        "{{ $antrians->where('taskid', 7)->count() }}",
                        "{{ $antrians->where('taskid', '>', 7)->count() }}",
                    ],
                    backgroundColor: [
                        '#d2d6de',
                        '#f56954',
                        '#f39c12',
                        '#00a65a',
                        '#f56954',
                        '#f39c12',
                        '#00a65a',
                        '#f56954',
                    ],
                }]
            }
            new Chart(donutChartCanvasTaskid, {
                type: 'doughnut',
                data: donutDataTaskid,
                options: donutOptions
            })
            //  method donat
            var donutChartCanvasMethod = $('#donutChartMethod').get(0).getContext('2d')
            var donutDataMethod = {
                labels: [
                    'Offline',
                    'Online',
                    'Other',
                ],
                datasets: [{
                    data: [
                        "{{ $antrians->where('method', 'OFF')->count() }}",
                        "{{ $antrians->where('method', 'ON')->count() }}",
                        "{{ $antrians->where('method', '!=', 'OFF')->where('method', '!=', 'ON')->count() }}",
                    ],
                    backgroundColor: [
                        '#d2d6de',
                        '#00a65a',
                        '#f39c12',
                    ],
                }]
            }
            new Chart(donutChartCanvasMethod, {
                type: 'doughnut',
                data: donutDataMethod,
                options: donutOptions
            })
            //  jenis pasien donat
            var donutChartCanvasMethod = $('#donutChartJenisPasien').get(0).getContext('2d')
            var donutDataJenisPasien = {
                labels: [
                    'JKN',
                    'NON JKN',
                    // 'Other',
                ],
                datasets: [{
                    data: [
                        "{{ $kunjungans->where('no_sep', '!=', null)->count() }}",
                        "{{ $kunjungans->where('no_sep', '==', null)->count() }}",
                    ],
                    backgroundColor: [
                        '#00a65a',
                        '#f39c12',
                    ],
                }]
            }
            new Chart(donutChartCanvasMethod, {
                type: 'doughnut',
                data: donutDataJenisPasien,
                options: donutOptions
            })

            //-------------
            //- PIE CHART -
            //-------------
            // Get context with jQuery - using jQuery's .get() method.
            // var pieChartCanvas = $('#pieChart').get(0).getContext('2d')
            // var pieData = donutData;
            // var pieOptions = {
            //     maintainAspectRatio: false,
            //     responsive: true,
            // }
            // //Create pie or douhnut chart
            // // You can switch between pie and douhnut using the method below.
            // new Chart(pieChartCanvas, {
            //     type: 'pie',
            //     data: pieData,
            //     options: pieOptions
            // })

            //-------------
            //- BAR CHART -
            //-------------
            // var barChartCanvas = $('#barChart').get(0).getContext('2d')
            // var barChartData = $.extend(true, {}, areaChartData)
            // var temp0 = areaChartData.datasets[0]
            // var temp1 = areaChartData.datasets[1]
            // barChartData.datasets[0] = temp1
            // barChartData.datasets[1] = temp0

            // var barChartOptions = {
            //     responsive: true,
            //     maintainAspectRatio: false,
            //     datasetFill: false
            // }

            // new Chart(barChartCanvas, {
            //     type: 'bar',
            //     data: barChartData,
            //     options: barChartOptions
            // })

            //---------------------
            //- STACKED BAR CHART -
            //---------------------
            // var stackedBarChartCanvas = $('#stackedBarChart').get(0).getContext('2d')
            // var stackedBarChartData = $.extend(true, {}, barChartData)

            // var stackedBarChartOptions = {
            //     responsive: true,
            //     maintainAspectRatio: false,
            //     scales: {
            //         xAxes: [{
            //             stacked: true,
            //         }],
            //         yAxes: [{
            //             stacked: true
            //         }]
            //     }
            // }

            // new Chart(stackedBarChartCanvas, {
            //     type: 'bar',
            //     data: stackedBarChartData,
            //     options: stackedBarChartOptions
            // })
        })
    </script>
@endsection
