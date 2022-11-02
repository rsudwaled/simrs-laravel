@extends('adminlte::page')
@section('title', 'Pasien Berdasarkan Daerah')
@section('content_header')
    <h1>Pasien Berdasarkan Daerah</h1>
@stop
@section('content')
    <div class="row">
        <div class="col-md-4">
            <x-adminlte-card title="Grafik Taskid Antrian Poliklinik" theme="primary" icon="fas fa-info-circle" collapsible>
                <canvas id="donutChartSex"
                    style="min-height: 200px; height: 200px; max-height: 200px; max-width: 100%;"></canvas>
                <br>
                <ul style="list-style-type:disc;">
                    <li>Data diambil dari tabel Pasien SIMRS</li>
                    <li>Jumlah Pasien Laki-Laki {{ $pasiens_laki }}</li>
                    <li>Jumlah Pasien Perempuan {{ $pasiens_perempuan }}</li>
                </ul>
            </x-adminlte-card>
        </div>
        <div class="col-md-4">
            <x-adminlte-card title="Grafik Taskid Antrian Poliklinik" theme="primary" icon="fas fa-info-circle" collapsible>
                <canvas id="donutChartPendidikan"
                    style="min-height: 200px; height: 200px; max-height: 200px; max-width: 100%;"></canvas>
                <br>
                <ul style="list-style-type:disc;">
                    <li>Data diambil dari tabel Pasien SIMRS</li>
                    <li>Jumlah Pasien Laki-Laki {{ $pasiens_laki }}</li>
                    <li>Jumlah Pasien Perempuan {{ $pasiens_perempuan }}</li>
                </ul>
            </x-adminlte-card>
        </div>

        <div class="col-6">
            <x-adminlte-card title="Data Pasien Berdasarkan 20 Kecataman Teratas" theme="secondary" collapsible>
                @php
                    $heads = ['Kode Kecamatan', 'Nama Kecamatan', 'Total (pasien)'];
                    $config = [
                        'paging' => false,
                        'searching' => false,
                        'info' => false,
                    ];
                @endphp
                <x-adminlte-datatable id="table1" :heads="$heads" :config="$config" hoverable bordered compressed>
                    @foreach ($pasiens_kecamatan as $item)
                        <tr>
                            <td>{{ $item->kode_kecamatan }}</td>
                            <td>{{ \App\Models\Kecamatan::firstWhere('kode_kecamatan', $item->kode_kecamatan)->nama_kecamatan }}
                            </td>
                            <td>{{ $item->total }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
        <div class="col-6">
            <x-adminlte-card title="Data Pasien Berdasarkan 20 Kabupaten Teratas" theme="secondary" collapsible>
                @php
                    $heads = ['Kode Kabupaten', 'Nama Kabupaten', 'Total (pasien)'];
                    $config = [
                        'paging' => false,
                        'searching' => false,
                        'info' => false,
                    ];
                @endphp
                <x-adminlte-datatable id="table2" :heads="$heads" :config="$config" hoverable bordered compressed>
                    @foreach ($pasiens_kabupaten as $item)
                        <tr>
                            <td>{{ $item->kode_kabupaten }}</td>
                            <td>{{ \App\Models\Kabupaten::firstWhere('kode_kabupaten_kota', $item->kode_kabupaten)->nama_kabupaten_kota }}
                            </td>
                            <td>{{ $item->total }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
        <div class="col-4">
            <x-adminlte-card title="Data Pasien Berdasarkan Pendidikan" theme="secondary" collapsible>
                @php
                    $heads = ['Kode', 'Pendidikan', 'Total (pasien)'];
                    $config = [
                        'paging' => false,
                        'searching' => false,
                        'info' => false,
                    ];
                @endphp
                <x-adminlte-datatable id="table3" :heads="$heads" :config="$config" hoverable bordered compressed>
                    @foreach ($pasiens_pendidikan as $item)
                        <tr>
                            <td>{{ $item->pendidikan }}</td>
                            <td>{{ $pendidikan->where('ID', $item->pendidikan)->first()->pendidikan }}</td>
                            <td>{{ $item->total }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
        <div class="col-4">
            <x-adminlte-card title="Data Pasien Berdasarkan Pekerjaan" theme="secondary" collapsible>
                @php
                    $heads = ['Kode', 'Pekerjaan', 'Total (pasien)'];
                    $config = [
                        'paging' => false,
                        'searching' => false,
                        'info' => false,
                    ];
                @endphp
                <x-adminlte-datatable id="table4" :heads="$heads" :config="$config" hoverable bordered compressed>
                    @foreach ($pasiens_pekerjaan as $item)
                        <tr>
                            <td>{{ $item->pekerjaan }}</td>
                            <td>{{ $pekerjaan->where('ID', $item->pekerjaan)->first() ? $pekerjaan->where('ID', $item->pekerjaan)->first()->pekerjaan : 'Belum Diisi' }}
                            </td>
                            <td>{{ $item->total }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
        <div class="col-4">
            <x-adminlte-card title="Data Pasien Berdasarkan Agama" theme="secondary" collapsible>
                @php
                    $heads = ['Kode', 'Agama', 'Total (pasien)'];
                    $config = [
                        'paging' => false,
                        'searching' => false,
                        'info' => false,
                    ];
                @endphp
                <x-adminlte-datatable id="table5" :heads="$heads" :config="$config" hoverable bordered compressed>
                    @foreach ($pasiens_agama as $item)
                        <tr>
                            <td>{{ $item->agama }}</td>
                            <td>{{ $agama->where('ID', $item->agama)->first() ? $agama->where('ID', $item->agama)->first()->agama : 'Belum Diisi' }}
                            </td>
                            <td>{{ $item->total }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Datatables', true)
@section('plugins.Chartjs', true)
@section('js')
    <script>
        $(function() {
            //  sex donat
            var donutOptions = {
                maintainAspectRatio: false,
                responsive: true,
            }
            var donutChartCanvasTaskid = $('#donutChartSex').get(0).getContext('2d')
            var donutDataTaskid = {
                labels: [
                    'Pasien Laki-Laki',
                    'Pasien Perempuan',
                ],
                datasets: [{
                    data: [
                        "{{ $pasiens_laki }}",
                        "{{ $pasiens_perempuan }}",
                    ],
                    backgroundColor: [
                        '#4293f5',
                        '#f0a3df',
                    ],
                }]
            }
            new Chart(donutChartCanvasTaskid, {
                type: 'doughnut',
                data: donutDataTaskid,
                options: donutOptions
            })
            //  pendidikan donat
            var donutOptions = {
                maintainAspectRatio: false,
                responsive: true,
            }
            var donutChartCanvasTaskid = $('#donutChartPendidikan').get(0).getContext('2d')
            var donutDataTaskid = {
                labels: [
                    'SD',
                    'SMP',
                    'SMA',
                    'D1',
                    'D2',
                    'D3',
                    'S1',
                    'S2',
                    'S3',
                    'Lainnya',
                    'Tidak Sekolah',
                    'Tidak Tamat SD',
                    'Tamat SD',
                    'Buta Huruf',
                    'TK',
                ],
                datasets: [{
                    data: [
                        "{{ $pasiens_pendidikan->where('pendidikan', 1)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 2)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 3)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 4)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 5)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 6)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 7)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 8)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 9)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 10)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 11)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 12)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 13)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 14)->first()->total }}",
                        "{{ $pasiens_pendidikan->where('pendidikan', 15)->first()->total }}",
                    ],
                    backgroundColor: [
                        '#4293f5',
                        '#f0a3df',
                    ],
                }]
            }
            new Chart(donutChartCanvasTaskid, {
                type: 'doughnut',
                data: donutDataTaskid,
                options: donutOptions
            })
        })
    </script>
@endsection
