@extends('adminlte::page')

@section('title', 'Antrian Pembayaran')

@section('content_header')
    <h1>Antrian Pembayaran</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            @if ($errors->any())
                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </x-adminlte-alert>
            @endif
            <x-adminlte-card title="Filter Data Antrian" theme="secondary" collapsible>
                <form action="{{ route('antrian.pembayaran') }}" method="get">
                    <div class="row">
                        <div class="col-md-3">
                            <x-adminlte-input name="user" label="User" readonly value="{{ Auth::user()->name }}" />
                        </div>
                        <div class="col-md-3">
                            @php
                                $config = ['format' => 'YYYY-MM-DD'];
                            @endphp
                            <x-adminlte-input-date name="tanggal" label="Tanggal Antrian" :config="$config"
                                value="{{ \Carbon\Carbon::parse($request->tanggal)->format('Y-m-d') }}">
                                <x-slot name="prependSlot">
                                    <div class="input-group-text bg-primary">
                                        <i class="fas fa-calendar-alt"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input-date>
                        </div>
                        <div class="col-md-3">
                            <x-adminlte-select name="loket" label="Loket">
                                <x-adminlte-options :options="[
                                    1 => 'Loket 1',
                                    2 => 'Loket 2',
                                    3 => 'Loket 3',
                                    4 => 'Loket 4',
                                    5 => 'Loket 5',
                                ]" :selected="$request->loket ?? 1" />
                            </x-adminlte-select>
                        </div>
                        <div class="col-md-3">
                            <x-adminlte-select name="lantai" label="Lantai">
                                <x-adminlte-options :options="[1 => 'Lantai 1', 2 => 'Lantai 2']" />
                            </x-adminlte-select>
                        </div>
                    </div>
                    <x-adminlte-button type="submit" class="withLoad" theme="primary" label="Submit Antrian" />
                </form>
            </x-adminlte-card>
            @if (isset($request->loket) && isset($request->lantai) && isset($request->tanggal))
                {{-- antrian belum pembayaran --}}
                <x-adminlte-card
                    title="Antrian Belum Melakukan Pembayaran ({{ $antrians->where('status_api', 0)->count() }} Orang)"
                    theme="primary" icon="fas fa-info-circle" collapsible>
                    @php
                        $heads = ['No', 'Kode', 'Tanggal', 'No RM / NIK', 'Pasien / Jenis', 'Poliklinik / Dokter', 'Status', 'Action'];
                        $config['order'] = ['7', 'asc'];
                    @endphp
                    <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" :config="$config" striped bordered
                        hoverable compressed>
                        @foreach ($antrians->where('status_api', '==', 0) as $item)
                            <tr>
                                <td>{{ $item->angkaantrean }}</td>
                                <td>{{ $item->kodebooking }}<br>
                                    {{ $item->nomorantrean }}
                                </td>
                                <td>{{ $item->tanggalperiksa }}</td>
                                <td>
                                    {{ $item->norm }} <br>
                                    {{ $item->nik }}
                                </td>
                                <td>
                                    {{ $item->nama }}<br>
                                    {{ $item->jenispasien }}
                                    @if ($item->pasienbaru == 1)
                                        <span class="badge bg-secondary">{{ $item->pasienbaru }}. Baru</span>
                                    @endif
                                    @if ($item->pasienbaru == 0)
                                        <span class="badge bg-secondary">{{ $item->pasienbaru }}. Lama</span>
                                    @endif
                                </td>
                                <td>{{ $item->namapoli }} {{ $item->jampraktek }}<br>{{ $item->namadokter }}
                                </td>
                                <td>
                                    @if ($item->taskid == 2)
                                        <span class="badge bg-danger">{{ $item->taskid }}. Pembayaran</span>
                                    @endif
                                    @if ($item->taskid == 3)
                                        @if ($item->status_api == 0)
                                            <span class="badge bg-warning">2. Belum Pembayaran</span>
                                        @else
                                            <span class="badge bg-success">{{ $item->taskid }}. Tunggu Poli</span>
                                        @endif
                                    @endif
                                    @if ($item->taskid == 4)
                                        <span class="badge bg-success">{{ $item->taskid }}. Periksa Poli</span>
                                    @endif
                                    @if ($item->taskid == 5)
                                        @if ($item->status_api == 1)
                                            <span class="badge bg-success">{{ $item->taskid }}. Tunggu Farmasi</span>
                                        @endif
                                        @if ($item->status_api == 2)
                                            <span class="badge bg-success">{{ $item->taskid }}. Selesai</span>
                                        @endif
                                    @endif
                                    @if ($item->taskid == 6)
                                        <span class="badge bg-success">{{ $item->taskid }}. Racik Obat</span>
                                    @endif
                                    @if ($item->taskid == 7)
                                        <span class="badge bg-success">{{ $item->taskid }}. Selesai</span>
                                    @endif
                                    @if ($item->taskid == 99)
                                        <span class="badge bg-danger">{{ $item->taskid }}. Batal</span>
                                    @endif
                                </td>
                                <td>
                                    @if ($item->status_api == 0)
                                        <x-adminlte-button class="btn-xs btnBayar withLoad" label="Bayar" theme="success"
                                            icon="fas fa-hand-holding-medical" data-toggle="tooltop" title="Bayar"
                                            data-id="{{ $item->id }}" />
                                    @endif
                                    <x-adminlte-button class="btn-xs" theme="danger" icon="fas fa-times"
                                        data-toggle="tooltop" title="Batal Antrian {{ $item->nomorantrean }}"
                                        onclick="window.location='{{ route('antrian.batal_antrian', $item->kodebooking) }}'" />
                                </td>
                            </tr>
                        @endforeach
                    </x-adminlte-datatable>
                </x-adminlte-card>
                {{-- antrian sudah pembayaran --}}
                <x-adminlte-card
                    title="Antrian Sudah Melakukan Pembayaran ({{ $antrians->where('status_api', 1)->count() }} Orang)"
                    theme="secondary" icon="fas fa-info-circle" collapsible>
                    @php
                        $heads = ['No', 'Kode', 'Tanggal', 'No RM / NIK', 'Pasien / Jenis', 'Poliklinik / Dokter', 'Status', 'Action'];
                        $config['order'] = ['6', 'asc'];
                    @endphp
                    <x-adminlte-datatable id="table2" class="nowrap" :heads="$heads" :config="$config" striped bordered
                        hoverable compressed>
                        @foreach ($antrians->where('status_api', '==', 1) as $item)
                            <tr>
                                <td>{{ $item->angkaantrean }}</td>
                                <td>{{ $item->kodebooking }}<br>
                                    {{ $item->nomorantrean }}
                                </td>
                                <td>{{ $item->tanggalperiksa }}</td>
                                <td>
                                    {{ $item->norm }} <br>
                                    {{ $item->nik }}
                                </td>
                                <td>
                                    {{ $item->nama }}<br>
                                    {{ $item->jenispasien }}
                                    @if ($item->pasienbaru == 1)
                                        <span class="badge bg-secondary">{{ $item->pasienbaru }}. Baru</span>
                                    @endif
                                    @if ($item->pasienbaru == 0)
                                        <span class="badge bg-secondary">{{ $item->pasienbaru }}. Lama</span>
                                    @endif
                                </td>
                                <td>{{ $item->namapoli }} {{ $item->jampraktek }}<br>{{ $item->namadokter }}
                                </td>
                                <td>
                                    @if ($item->taskid == 2)
                                        <span class="badge bg-danger">{{ $item->taskid }}. Pembayaran</span>
                                    @endif
                                    @if ($item->taskid == 3)
                                        @if ($item->status_api == 0)
                                            <span class="badge bg-warning">2. Belum Pembayaran</span>
                                        @else
                                            <span class="badge bg-success">{{ $item->taskid }}. Tunggu Poli</span>
                                        @endif
                                    @endif
                                    @if ($item->taskid == 4)
                                        <span class="badge bg-success">{{ $item->taskid }}. Periksa Poli</span>
                                    @endif
                                    @if ($item->taskid == 5)
                                        @if ($item->status_api == 0)
                                            <span class="badge bg-success">{{ $item->taskid }}. Tunggu Farmasi</span>
                                        @endif
                                        @if ($item->status_api == 1)
                                            <span class="badge bg-success">{{ $item->taskid }}. Selesai</span>
                                        @endif
                                    @endif
                                    @if ($item->taskid == 6)
                                        <span class="badge bg-success">{{ $item->taskid }}. Racik Obat</span>
                                    @endif
                                    @if ($item->taskid == 7)
                                        <span class="badge bg-success">{{ $item->taskid }}. Selesai</span>
                                    @endif
                                    @if ($item->taskid == 99)
                                        <span class="badge bg-danger">{{ $item->taskid }}. Batal</span>
                                    @endif
                                </td>
                                <td>
                                    @if ($item->status_api == 0)
                                        <x-adminlte-button class="btn-xs btnBayar withLoad" label="Bayar" theme="success"
                                            icon="fas fa-hand-holding-medical" data-toggle="tooltop" title="Bayar"
                                            data-id="{{ $item->id }}" />
                                    @endif
                                    <x-adminlte-button class="btn-xs" theme="danger" icon="fas fa-times"
                                        data-toggle="tooltop" title="Batal Antrian {{ $item->nomorantrean }}"
                                        onclick="window.location='{{ route('antrian.batal_antrian', $item->kodebooking) }}'" />
                                </td>
                            </tr>
                        @endforeach
                    </x-adminlte-datatable>
                </x-adminlte-card>
            @endif
        </div>
    </div>
    <x-adminlte-modal id="modalPembayaran" title="Pembayaran Antrian Pasien" size="lg" theme="success"
        icon="fas fa-user-plus" v-centered>
        <form name="formBayar" id="formBayar" action="{{ route('antrian.update_pembayaran') }}" method="post">
            @csrf
            <input type="hidden" name="antrianid" id="antrianid" value="">
            <dl class="row">
                <dt class="col-sm-3">Kode Booking</dt>
                <dd class="col-sm-8">: <span id="kodebooking"></span></dd>
                <dt class="col-sm-3">Antrian</dt>
                <dd class="col-sm-8">: <span id="angkaantrean"></span> / <span id="nomorantrean"></span></dd>
                <dt class="col-sm-3 ">Tanggal Perikasa</dt>
                <dd class="col-sm-8">: <span id="tanggalperiksa"></span></dd>
                <dt class="col-sm-3">Administrator</dt>
                <dd class="col-sm-8">: {{ Auth::user()->name }}</dd>
            </dl>
            <x-adminlte-card theme="primary" title="Informasi Kunjungan Berobat">
                <div class="row">
                    <div class="col-md-5">
                        <dl class="row">
                            <dt class="col-sm-4">No RM</dt>
                            <dd class="col-sm-8">: <span id="norm"></span></dd>
                            <dt class="col-sm-4">NIK</dt>
                            <dd class="col-sm-8">: <span id="nik"></span></dd>
                            <dt class="col-sm-4">No BPJS</dt>
                            <dd class="col-sm-8">: <span id="nomorkartu"></span></dd>
                            <dt class="col-sm-4">Nama</dt>
                            <dd class="col-sm-8">: <span id="nama"></span></dd>
                            <dt class="col-sm-4">No HP</dt>
                            <dd class="col-sm-8">: <span id="nohp"></span></dd>
                        </dl>
                    </div>
                    <div class="col-md-7">
                        <dl class="row">
                            <dt class="col-sm-4">No Rujukan</dt>
                            <dd class="col-sm-8">: <span id="nomorreferensi"></span></dd>
                            <dt class="col-sm-4">Poliklinik</dt>
                            <dd class="col-sm-8">: <span id="namapoli"></span></dd>
                            <dt class="col-sm-4">Dokter</dt>
                            <dd class="col-sm-8">: <span id="namadokter"></span></dd>
                            <dt class="col-sm-4">Jadwal</dt>
                            <dd class="col-sm-8">: <span id="jampraktek"></span></dd>
                            <dt class="col-sm-4">Jenis Kunjungan</dt>
                            <dd class="col-sm-8">: <span id="jeniskunjungan"></span></dd>
                        </dl>
                    </div>
                </div>
            </x-adminlte-card>
            <x-adminlte-card theme="primary" title="Informasi Biaya Berobat">
                <div class="row">
                    <table>

                    </table>
                    <div class="col-md-6">
                        <x-adminlte-input name="biaya" label="Biaya Dibayarkan" placeholder="Biaya Dibayarkan"
                            enable-old-support />
                    </div>
                </div>
            </x-adminlte-card>
            <x-slot name="footerSlot">
                <x-adminlte-button label="Bayar" form="formBayar" class="mr-auto" type="submit" theme="success"
                    icon="fas fa-money-bill" />
                <x-adminlte-button theme="danger" label="Dismiss" data-dismiss="modal" />
            </x-slot>
        </form>
    </x-adminlte-modal>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
@section('plugins.TempusDominusBs4', true)

@section('js')
    <script>
        $(function() {
            $('.btnBayar').click(function() {
                var antrianid = $(this).data('id');
                $.LoadingOverlay("show");
                $.get("{{ route('antrian.index') }}" + '/' + antrianid + '/edit', function(data) {
                    // console.log(data);
                    $('#kodebooking').html(data.kodebooking);
                    $('#angkaantrean').html(data.angkaantrean);
                    $('#nomorantrean').html(data.nomorantrean);
                    $('#tanggalperiksa').html(data.tanggalperiksa);

                    $('#norm').html(data.norm);
                    $('#nik').html(data.nik);
                    $('#nomorkartu').html(data.nomorkartu);
                    $('#nama').html(data.nama);
                    $('#nohp').html(data.nohp);

                    $('#nomorreferensi').html(data.nomorreferensi);
                    $('#namapoli').html(data.namapoli);
                    $('#namadokter').html(data.namadokter);
                    $('#jampraktek').html(data.jampraktek);
                    $('#jeniskunjungan').html(data.jeniskunjungan);

                    $('#user').html(data.user);
                    $('#antrianid').val(antrianid);
                    $('#namapoli').val(data.namapoli);
                    $('#namadokter').val(data.namadokter);
                    $('#kodepoli').val(data.kodepoli);
                    $('#kodedokter').val(data.kodedokter);
                    $('#jampraktek').val(data.jampraktek);
                    // $('#kodepoli').val(data.kodepoli).trigger('change');
                    $('#modalPembayaran').modal('show');
                    $.LoadingOverlay("hide", true);
                })
            });
        });
    </script>
@endsection
