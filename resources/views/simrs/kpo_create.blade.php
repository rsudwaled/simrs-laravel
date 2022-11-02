@extends('adminlte::page')

@section('title', 'KPO Elektronik')

@section('content_header')
    <h1>KPO Elektronik</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-4">
            <x-adminlte-card title="Data Pasien" theme="warning" collapsible>
                <x-adminlte-input fgroup-class="norm" name="norm" label="No RM" type="number">
                    <x-slot name="appendSlot">
                        <x-adminlte-button onclick="cekPasien();" theme="success" label="Cek" />
                    </x-slot>
                </x-adminlte-input>
                <dl class="row">
                    <dt class="col-sm-3">Nama</dt>
                    <dd class="col-sm-9">: -</dd>
                    <dt class="col-sm-3">Alamat</dt>
                    <dd class="col-sm-9">: -</dd>
                    <dt class="col-sm-3">Dokter DPJP</dt>
                    <dd class="col-sm-9">: -</dd>
                    <dt class="col-sm-3">Ruangan</dt>
                    <dd class="col-sm-9">: -</dd>
                    <dt class="col-sm-3">Dokter</dt>
                    <dd class="col-sm-9">: -</dd>
                    <dt class="col-sm-3">Nama</dt>
                    <dd class="col-sm-9">: -</dd>
                </dl>

            </x-adminlte-card>
            <div class="card card-primary card-tabs">
                <div class="card-header p-0 pt-1">
                    <ul class="nav nav-tabs" id="custom-tabs-two-tab" role="tablist">
                        <li class="pt-2 px-3">
                            <h3 class="card-title"><b>Diagnosa</b></h3>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link active" id="custom-tabs-two-home-tab" data-toggle="pill"
                                href="#custom-tabs-two-home" role="tab" aria-controls="custom-tabs-two-home"
                                aria-selected="true">Infeksi</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" id="custom-tabs-two-profile-tab" data-toggle="pill"
                                href="#custom-tabs-two-profile" role="tab" aria-controls="custom-tabs-two-profile"
                                aria-selected="false">ICD-10</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" id="custom-tabs-two-profile-tab" data-toggle="pill"
                                href="#custom-tabs-two-messages" role="tab" aria-controls="custom-tabs-two-messages"
                                aria-selected="false">ICD-9</a>
                        </li>
                    </ul>
                </div>
                <div class="card-body">
                    <div class="tab-content" id="custom-tabs-two-tabContent">
                        <div class="tab-pane fade show active" id="custom-tabs-two-home" role="tabpanel"
                            aria-labelledby="custom-tabs-two-home-tab">
                            <div class="form-group">
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="sepsis" value="sepsis">
                                    <label for="sepsis" class="custom-control-label">Sepsis</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="pnemonia-bakterial"
                                        value="pnemonia-bakterial">
                                    <label for="pnemonia-bakterial" class="custom-control-label">Pnemonia Bakterial</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="intraabdomen-komplikata"
                                        value="intraabdomen-komplikata">
                                    <label for="intraabdomen-komplikata" class="custom-control-label">Infeksi Intra-abdomen
                                        Komplikata</label>
                                </div>
                                <br>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="meningitis-encefalitis"
                                        value="meningitis-encefalitis">
                                    <label for="meningitis-encefalitis" class="custom-control-label">Meningitis /
                                        Encefalitis Bakterial</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Kulit &
                                        Jaringan</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Mata /
                                        Telinga</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Sendi &
                                        Tulang</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Pnemonia Non
                                        Bakterial</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Saluran Cerna /
                                        Hepatobilier Pancreas</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Ginjal & Saluran
                                        Kemih</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Otak & Sumsum
                                        Tulang</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Obsteri /
                                        Ginekologi</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi TB Paru</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi TB Extra
                                        Paru</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">LEPRA</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Jamur</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Virus</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Non Infeksi
                                        (Inflamasi)</label>
                                </div>
                            </div>
                        </div>
                        <div class="tab-pane fade" id="custom-tabs-two-profile" role="tabpanel"
                            aria-labelledby="custom-tabs-two-profile-tab">
                            @php
                                $config = [
                                    'placeholder' => 'Select multiple options...',
                                    'allowClear' => true,
                                ];
                            @endphp
                            <x-adminlte-select2 id="sel2Category" name="sel2Category[]" label="Diagnosa ICD-10"
                                :config="$config" multiple>
                                @foreach ($roles as $role)
                                    <option value="{{ $role->diag }}">
                                        {{ $role->diag }} - {{ $role->nama }}
                                    </option>
                                @endforeach
                            </x-adminlte-select2>
                        </div>
                        <div class="tab-pane fade" id="custom-tabs-two-messages" role="tabpanel"
                            aria-labelledby="custom-tabs-two-messages-tab">
                            Morbi turpis dolor, vulputate vitae felis non, tincidunt congue mauris. Phasellus volutpat augue
                            id mi placerat mollis. Vivamus faucibus eu massa eget condimentum. Fusce nec hendrerit sem, ac
                            tristique nulla. Integer vestibulum orci odio. Cras nec augue ipsum. Suspendisse ut velit
                            condimentum, mattis urna a, malesuada nunc. Curabitur eleifend facilisis velit finibus
                            tristique. Nam vulputate, eros non luctus efficitur, ipsum odio volutpat massa, sit amet
                            sollicitudin est libero sed ipsum. Nulla lacinia, ex vitae gravida fermentum, lectus ipsum
                            gravida arcu, id fermentum metus arcu vel metus. Curabitur eget sem eu risus tincidunt eleifend
                            ac ornare magna.
                        </div>
                    </div>
                </div>
                <!-- /.card -->
            </div>
        </div>
        <div class="col-8">
            <div class="card card-primary card-tabs">
                <div class="card-header p-0 pt-1">
                    <ul class="nav nav-tabs" id="custom-tabs-two-tab" role="tablist">
                        <li class="pt-2 px-3">
                            <h3 class="card-title"><b>Riwayat Pasien</b></h3>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link active" id="tab-order-obat" data-toggle="pill"
                                href="#custom-tabs-two-home" role="tab" aria-controls="custom-tabs-two-home"
                                aria-selected="true">List Order Obat</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" id="tab-evaluasi-antibiotik" data-toggle="pill"
                                href="#custom-tabs-two-profile" role="tab" aria-controls="custom-tabs-two-profile"
                                aria-selected="false">Evaluasi Antibiotik</a>
                        </li>
                    </ul>
                </div>
                <div class="card-body">
                    <div class="tab-content" id="custom-tabs-two-tabContent">
                        <div class="tab-pane fade show active" id="custom-tabs-two-home" role="tabpanel"
                            aria-labelledby="custom-tabs-two-home-tab">
                            <div class="form-group">
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="sepsis" value="sepsis">
                                    <label for="sepsis" class="custom-control-label">Sepsis</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="pnemonia-bakterial"
                                        value="pnemonia-bakterial">
                                    <label for="pnemonia-bakterial" class="custom-control-label">Pnemonia
                                        Bakterial</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="intraabdomen-komplikata"
                                        value="intraabdomen-komplikata">
                                    <label for="intraabdomen-komplikata" class="custom-control-label">Infeksi
                                        Intra-abdomen
                                        Komplikata</label>
                                </div>
                                <br>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="meningitis-encefalitis"
                                        value="meningitis-encefalitis">
                                    <label for="meningitis-encefalitis" class="custom-control-label">Meningitis /
                                        Encefalitis Bakterial</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Kulit &
                                        Jaringan</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Mata /
                                        Telinga</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Sendi &
                                        Tulang</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Pnemonia Non
                                        Bakterial</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Saluran Cerna /
                                        Hepatobilier Pancreas</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Ginjal & Saluran
                                        Kemih</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Otak & Sumsum
                                        Tulang</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Obsteri /
                                        Ginekologi</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi TB Paru</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi TB Extra
                                        Paru</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">LEPRA</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Jamur</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Infeksi Virus</label>
                                </div>
                                <div class="custom-control custom-checkbox">
                                    <input class="custom-control-input" type="checkbox" id="customCheckbox1"
                                        value="option1">
                                    <label for="customCheckbox1" class="custom-control-label">Non Infeksi
                                        (Inflamasi)</label>
                                </div>
                            </div>
                        </div>
                        <div class="tab-pane fade" id="custom-tabs-two-profile" role="tabpanel"
                            aria-labelledby="custom-tabs-two-profile-tab">
                            @php
                                $config = [
                                    'placeholder' => 'Select multiple options...',
                                    'allowClear' => true,
                                ];
                            @endphp
                            <x-adminlte-select2 id="sel2Category" name="sel2Category[]" label="Diagnosa ICD-10"
                                :config="$config" multiple>
                                @foreach ($roles as $role)
                                    <option value="{{ $role->diag }}">
                                        {{ $role->diag }} - {{ $role->nama }}
                                    </option>
                                @endforeach
                            </x-adminlte-select2>
                        </div>
                        <div class="tab-pane fade" id="custom-tabs-two-messages" role="tabpanel"
                            aria-labelledby="custom-tabs-two-messages-tab">
                            Morbi turpis dolor, vulputate vitae felis non, tincidunt congue mauris. Phasellus volutpat augue
                            id mi placerat mollis. Vivamus faucibus eu massa eget condimentum. Fusce nec hendrerit sem, ac
                            tristique nulla. Integer vestibulum orci odio. Cras nec augue ipsum. Suspendisse ut velit
                            condimentum, mattis urna a, malesuada nunc. Curabitur eleifend facilisis velit finibus
                            tristique. Nam vulputate, eros non luctus efficitur, ipsum odio volutpat massa, sit amet
                            sollicitudin est libero sed ipsum. Nulla lacinia, ex vitae gravida fermentum, lectus ipsum
                            gravida arcu, id fermentum metus arcu vel metus. Curabitur eget sem eu risus tincidunt eleifend
                            ac ornare magna.
                        </div>
                    </div>
                </div>
                <!-- /.card -->
            </div>
        </div>
    </div>

@stop

@section('plugins.Select2', true)
