@extends('adminlte::page')

@section('title', 'Surat Kontrol Poliklinik')

@section('content_header')
    <h1>Surat Kontrol Poliklinik</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Filter Data Kunjungan" theme="secondary" collapsible>
                <form action="{{ route('antrian.surat_kontrol_poli') }}" method="get">
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
                            @can('admin')
                                <x-adminlte-select2 name="kodepoli" label="Poliklinik">
                                    <option value="">00000 - SEMUA POLIKLINIK</option>
                                    @foreach ($unit as $item)
                                        <option value="{{ $item->KDPOLI }}"
                                            {{ $item->KDPOLI == $request->kodepoli ? 'selected' : null }}>
                                            {{ $item->KDPOLI }}
                                            -
                                            {{ $item->nama_unit }}
                                        </option>
                                    @endforeach
                                </x-adminlte-select2>
                            @else
                                @can('poliklinik')
                                    <x-adminlte-input name="kodepoli" label="Poliklinik" readonly
                                        value="{{ Auth::user()->username }}" />
                                @endcan
                            @endcan
                        </div>
                        <div class="col-md-3">
                            <x-adminlte-select2 name="kodedokter" label="Dokter">
                                <option value="">00000 - SEMUA DOKTER</option>
                                @foreach ($dokters as $item)
                                    <option value="{{ $item->kode_dokter_jkn }}"
                                        {{ $item->kode_dokter_jkn == $request->kodedokter ? 'selected' : null }}>
                                        {{ $item->kode_dokter_jkn }} -
                                        {{ $item->nama_paramedis }}
                                    </option>
                                @endforeach
                            </x-adminlte-select2>
                        </div>
                    </div>
                    <x-adminlte-button type="submit" class="withLoad" theme="primary" label="Submit Antrian" />
                </form>
            </x-adminlte-card>
            @if (isset($kunjungans))
                <div class="row">
                    <div class="col-md-4">
                        <x-adminlte-card title="Buat Surat Kontrol Pasien" theme="success" collapsible>
                            @if ($errors->any())
                                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                                    <ul>
                                        @foreach ($errors->all() as $error)
                                            <li>{{ $error }}</li>
                                        @endforeach
                                    </ul>
                                </x-adminlte-alert>
                            @endif
                            <form action="{{ route('vclaim.buat_surat_kontrol') }}" id="formSuratKontrol" method="post">
                                @csrf
                                @php
                                    $config = [
                                        'format' => 'YYYY-MM-DD',
                                        'dayViewHeaderFormat' => 'MMM YYYY',
                                        'minDate' => 'js:moment()',
                                        'daysOfWeekDisabled' => [0],
                                    ];
                                @endphp
                                <x-adminlte-input name="nomorsep_suratkontrol" placeholder="Nomor SEP" label="Nomor SEP" />
                                <x-adminlte-input-date name="tanggal_suratkontrol" label="Tanggal Surat Kontrol"
                                    :config="$config" placeholder="Pilih Tanggal Surat Kontrol ..."
                                    value="{{ Carbon\Carbon::now()->format('Y-m-d') }}">
                                    <x-slot name="prependSlot">
                                        <div class="input-group-text bg-primary">
                                            <i class="fas fa-calendar-alt"></i>
                                        </div>
                                    </x-slot>
                                </x-adminlte-input-date>
                                <x-adminlte-select2 name="kodepoli_suratkontrol" label="Nama Poliklinik">
                                    @foreach ($unit as $item)
                                        <option value="{{ $item->KDPOLI }}"
                                            {{ $item->KDPOLI == $request->kodepoli ? 'selected' : null }}>
                                            {{ $item->KDPOLI }} -
                                            {{ $item->nama_unit }}
                                        </option>
                                    @endforeach
                                </x-adminlte-select2>
                                <x-adminlte-select2 name="kodedokter_suratkontrol" label="DPJP Surat Kontrol">
                                    @foreach ($dokters as $item)
                                        <option value="{{ $item->kode_dokter_jkn }}"
                                            {{ $item->kode_dokter_jkn == $request->kodedokter ? 'selected' : null }}>
                                            {{ $item->kode_dokter_jkn }} -
                                            {{ $item->nama_paramedis }}
                                        </option>
                                    @endforeach
                                </x-adminlte-select2>
                                <x-slot name="footerSlot">
                                    <button type="submit" form="formSuratKontrol" value="Submit"
                                        class="mr-auto btn btn-success withLoad">Buat Surat Kontrol</button>
                                    <x-adminlte-button theme="danger" label="Reset" />
                                </x-slot>
                            </form>
                        </x-adminlte-card>
                    </div>
                    <div class="col-md-8">
                        <x-adminlte-card title="Kunjungan Poliklinik ({{ $kunjungans->count() }} Orang)" theme="primary"
                            icon="fas fa-info-circle" collapsible>
                            @php
                                $heads = ['Tgl Kunjungan', 'Pasien', 'SEP', 'Rujukan', 'Poliklinik'];
                                // $config['order'] = ['7', 'asc'];S
                            @endphp
                            <x-adminlte-datatable id="table2" class="nowrap text-xs" :heads="$heads" striped bordered
                                hoverable compressed>
                                @foreach ($kunjungans as $item)
                                    <tr class={{ $item->surat_kontrol ? 'text-success' : null }}>
                                        <td>
                                            {{ $item->tgl_masuk }}
                                            <br>{{ $item->kode_kunjungan }}
                                        </td>
                                        <td>
                                            RM : {{ $item->no_rm }}<br><b>{{ $item->pasien->nama_px }}</b><br>
                                            {{ $item->pasien->no_Bpjs }}
                                        </td>
                                        <td>{{ $item->no_sep }}</td>
                                        <td>{{ $item->no_rujukan }}</td>
                                        <td>{{ $item->unit->nama_unit }}<br>{{ $item->dokter->nama_paramedis }}</td>
                                    </tr>
                                @endforeach
                            </x-adminlte-datatable>
                            Warna teks hijau adalah kunjungan yang telah dibuatkan surat kontrol.
                        </x-adminlte-card>
                    </div>
                </div>
                <x-adminlte-card title="Surat Kontrol Poliklinik ({{ $surat_kontrols->count() }})" theme="primary"
                    icon="fas fa-info-circle" collapsible>
                    @php
                        $heads = ['Tgl Dibuat', 'Tgl S. Kontrol', 'Action', 'No S. Kontrol', 'Poliklinik', 'Pasien', 'Kartu', 'No SEP Asal', 'Dokter'];
                        $config = [
                            'order' => ['2', 'desc'],
                            'paging' => false,
                        ];
                    @endphp
                    <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" :config="$config" striped bordered
                        hoverable compressed>
                        @foreach ($surat_kontrols as $item)
                            <tr>
                                <td>{{ $item->tglTerbitKontrol }}</td>
                                <td>{{ $item->tglRencanaKontrol }}</td>
                                <td>
                                    <x-adminlte-button class="btn-xs btnEditSuratKontrol" label="Edit" theme="warning"
                                        icon="fas fa-edit" data-toggle="tooltop" title="Edit Surat Kontrol"
                                        data-id="{{ $item->id }}" />
                                </td>
                                <td>{{ $item->noSuratKontrol }}</td>
                                <td>{{ $item->namaPoliTujuan }}</td>
                                <td>{{ $item->nama }}</td>
                                <td>{{ $item->noKartu }}</td>
                                <td>{{ $item->noSepAsalKontrol }}</td>
                                <td>{{ $item->namaDokter }}</td>
                            </tr>
                        @endforeach
                    </x-adminlte-datatable>
                </x-adminlte-card>
                <x-adminlte-modal id="modalSuratKontrol" name="modalSuratKontrol" title="Edit Surat Kontrol Rawat Jalan"
                    theme="warning" icon="fas fa-file-medical" v-centered>
                    <form action="{{ route('vclaim.update_surat_kontrol') }}" id="formEditSuratKontrol" method="post">
                        @csrf
                        @php
                            $config = [
                                'format' => 'YYYY-MM-DD',
                                'dayViewHeaderFormat' => 'MMM YYYY',
                                'minDate' => "js:moment().add(1, 'days')",
                                'daysOfWeekDisabled' => [0],
                            ];
                        @endphp
                        <x-adminlte-input name="nama_suratkontrol_edit" placeholder="Nama Pasien" label="Nama Pasien"
                            readonly />
                        <div class="row">
                            <div class="col-md-6">
                                <x-adminlte-input name="nomor_suratkontrol_edit" placeholder="Nomor Surat Kontrol"
                                    label="Nomor Surat Kontrol" readonly />
                            </div>
                            <div class="col-md-6">
                                <x-adminlte-input name="nomorsep_suratkontrol_edit" placeholder="Nomor SEP"
                                    label="Nomor SEP" readonly />
                            </div>
                        </div>
                        <x-adminlte-input-date name="tanggal_suratkontrol_edit" label="Tanggal Rencana Surat Kontrol"
                            :config="$config" placeholder="Pilih Tanggal Surat Kontrol ..."
                            value="{{ Carbon\Carbon::now()->format('Y-m-d') }}">
                            <x-slot name="prependSlot">
                                <div class="input-group-text bg-primary">
                                    <i class="fas fa-calendar-alt"></i>
                                </div>
                            </x-slot>
                        </x-adminlte-input-date>
                        <x-adminlte-select2 name="kodepoli_suratkontrol_edit" label="Poliklinik">
                            <option value="">00000 - SEMUA POLIKLINIK</option>
                            @foreach ($unit as $item)
                                <option value="{{ $item->KDPOLI }}"
                                    {{ $item->KDPOLI == $request->kodepoli ? 'selected' : null }}>
                                    {{ $item->KDPOLI }}
                                    -
                                    {{ $item->nama_unit }}
                                </option>
                            @endforeach
                        </x-adminlte-select2>
                        <x-adminlte-select2 name="kodedokter_suratkontrol_edit" label="DPJP Surat Kontrol">
                            @foreach ($dokters as $item)
                                <option value="{{ $item->kode_dokter_jkn }}"
                                    {{ $item->kode_dokter_jkn == $request->kodedokter ? 'selected' : null }}>
                                    {{ $item->kode_dokter_jkn }} -
                                    {{ $item->nama_paramedis }}
                                </option>
                            @endforeach
                        </x-adminlte-select2>
                        <x-slot name="footerSlot">
                            <button type="submit" form="formEditSuratKontrol" value="Submit"
                                class="mr-auto btn btn-success withLoad">Update
                                Surat
                                Kontrol</button>
                            <x-adminlte-button theme="danger" label="Tutup" data-dismiss="modal" />
                        </x-slot>
                    </form>
                </x-adminlte-modal>
            @endif

        </div>
    </div>

@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
@section('plugins.TempusDominusBs4', true)
@section('js')
    <script>
        $(function() {
            $('.btnEditSuratKontrol').click(function() {
                var nomorsuratkontrol = $(this).data('id');
                var url = "{{ route('vclaim.index') }}" + "/edit_surat_kontrol/" + nomorsuratkontrol;
                $.LoadingOverlay("show");
                $.get(url, function(data) {
                    console.log(data);
                    $('#nama_suratkontrol_edit').val(data.nama);
                    $('#nomor_suratkontrol_edit').val(data.noSuratKontrol);
                    $('#nomorsep_suratkontrol_edit').val(data.noSepAsalKontrol);
                    $('#tanggal_suratkontrol_edit').val(data.tglRencanaKontrol);
                    $('#kodepoli_suratkontrol_edit').val(data.poliTujuan).trigger('change');
                    $('#kodedokter_suratkontrol_edit').val(data.kodeDokter).trigger('change');
                    $('#modalSuratKontrol').modal('show');
                    $.LoadingOverlay("hide", true);
                });
            });
        });
    </script>
@endsection
