@extends('adminlte::page')

@section('title', 'Referensi Poliklinik')

@section('content_header')
    <h1>Referensi Poliklinik</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-md-6">
            <x-adminlte-card title="Poliklinik Aktif RSUD Waled" theme="info" icon="fas fa-info-circle" collapsible
                maximizable>
                @php
                    $heads = ['Nama Poliklinik', 'Subspesialis', 'Lokasi', 'Daftar', 'Status'];
                    $config['paging'] = false;
                @endphp
                <x-adminlte-datatable id="table1" :heads="$heads" :config="$config" striped bordered hoverable
                    compressed>
                    @foreach ($polis->where('status', 1) as $item)
                        <tr>
                            {{-- <td>{{ $item->kodepoli }}</td> --}}
                            {{-- <td>{{ $item->namapoli }}</td> --}}
                            <td>{{ $item->kodesubspesialis }} - {{ $item->namasubspesialis }}</td>
                            <td>
                                @if ($item->subspesialis)
                                    Ya <i class="fas fa-check-circle text-success"></i>
                                @else
                                    Bukan <i class="fas fa-times-circle text-danger"></i>
                                @endif
                            </td>
                            <td>{{ $item->lokasi }}</td>
                            <td>{{ $item->lantaipendaftaran }}</td>
                            <td>
                                @if ($item->status == 1)
                                    <a href="{{ route('poli.edit', $item->id) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="aktif" theme="success"
                                            title="Klik untuk non-aktifkan" />
                                    </a>
                                @else
                                    <a href="{{ route('poli.edit', $item->id) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="nonaktif" theme="danger"
                                            data-toggle="tooltip" title="Klik untuk aktifkan" />
                                    </a>
                                @endif
                                <x-adminlte-button class="btn-xs btnEditPoli" theme="warning" icon="fas fa-edit"
                                    data-toggle="tooltip" title="Edit Poliklinik" data-id="{{ $item->id }}" />
                            </td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
        <div class="col-md-6">
            <x-adminlte-card title="Data Semua Poliklinik" theme="info" icon="fas fa-info-circle" collapsible maximizable>
                @php
                    $heads = ['Kode Poli', 'Nama Poli', 'Spesialis', 'Status'];
                @endphp
                <x-adminlte-datatable id="table3" :heads="$heads" striped bordered hoverable compressed>
                    @foreach ($polis as $item)
                        <tr>
                            <td>{{ $item->kodesubspesialis }}</td>
                            <td>{{ $item->namasubspesialis }}</td>
                            <td>
                                @if ($item->subspesialis)
                                    Ya <i class="fas fa-check-circle text-success"></i>
                                @else
                                    Bukan <i class="fas fa-times-circle text-danger"></i>
                                @endif
                            </td>
                            <td>
                                @if ($item->status == 1)
                                    <a href="{{ route('poli.edit', $item->id) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="aktif" theme="success"
                                            title="Klik untuk non-aktifkan" />
                                    </a>
                                @else
                                    <a href="{{ route('poli.edit', $item->id) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="nonaktif" theme="danger"
                                            data-toggle="tooltop" title="Klik untuk aktifkan" />
                                    </a>
                                @endif
                            </td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
                <a href="{{ route('poli.create') }}" class="btn btn-success">Create Poliklinik</a>
            </x-adminlte-card>
        </div>
    </div>
    {{-- modal poliklinik --}}
    <x-adminlte-modal id="modalPoli" name="modalPoli" title="Poliklinik" theme="warning"
        icon="fas fa-prescription-bottle-alt" static-backdrop>
        <form name="formUpdatePoli" id="formUpdatePoli" action="{{ route('poli.store') }}" method="POST">
            @csrf
            <input type="hidden" name="method" value="UPDATE">
            <input type="hidden" name="idpoli" id="idpoli">
            <div class="row">
                <div class="col-md-6">
                    <x-adminlte-input name="kodepoli" label="Kode Poliklinik" placeholder="Kode Poliklinik"
                        enable-old-support readonly />
                </div>
                <div class="col-md-6">
                    <x-adminlte-input name="namapoli" label="Nama Poliklinik" placeholder="Nama Poliklinik"
                        enable-old-support readonly />
                </div>
                <div class="col-md-6">
                    <x-adminlte-input name="kodesubspesialis" label="Kode Subspesialis" placeholder="Kode Subspesialis"
                        enable-old-support readonly />
                </div>
                <div class="col-md-6">
                    <x-adminlte-input name="namasubspesialis" label="Nama Subspesialis" placeholder="Nama Subspesialis"
                        enable-old-support readonly />
                </div>
                <div class="col-md-4">
                    <x-adminlte-input name="lokasi" label="Lokasi Poliklinik" placeholder="Lokasi Poliklinik"
                        enable-old-support />
                </div>
                <div class="col-md-4">
                    <x-adminlte-input name="lantaipendaftaran" label="Lantai Pendaftaran" placeholder="Lantai Pendaftaran"
                        enable-old-support />
                </div>
                <div class="col-md-4">
                    <input type="hidden" name="status" value="false">
                    <x-adminlte-input-switch name="status" label="Stasus Aktif" data-on-text="YES" data-off-text="NO"
                        data-on-color="primary" />
                </div>
            </div>
            <x-slot name="footerSlot">
                <x-adminlte-button label="Update" form="formUpdatePoli" class="mr-auto withLoad" type="submit"
                    theme="success" icon="fas fa-edit" />
                <x-adminlte-button theme="danger" icon="fas fa-times" label="Close" data-dismiss="modal" />
            </x-slot>
        </form>
    </x-adminlte-modal>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
@section('plugins.BootstrapSwitch', true)
@section('js')
    <script>
        $(function() {
            $.ajaxSetup({
                headers: {
                    'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
                }
            });
            $('.btnEditPoli').click(function() {
                var idpoli = $(this).data('id');
                $('#modalPoli').modal('show');
                $.LoadingOverlay("show");
                $.get("{{ route('poli.index') }}" + '/' + idpoli, function(data) {
                    console.log(data);
                    $('#idpoli').val(idpoli);
                    $('#kodepoli').val(data.kodepoli);
                    $('#namapoli').val(data.namapoli);
                    $('#kodesubspesialis').val(data.kodesubspesialis);
                    $('#namasubspesialis').val(data.namasubspesialis);
                    $('#lokasi').val(data.lokasi);
                    $('#lantaipendaftaran').val(data.lantaipendaftaran);
                    if (data.status == 1) {
                        $('#status').prop('checked', true).trigger('change');
                    }
                    $('#modalPoli').modal('show');
                    $.LoadingOverlay("hide", true);
                })
            });
        });
    </script>
@endsection
